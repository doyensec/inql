package inql.history

import burp.Burp
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import inql.Config
import inql.InQL
import inql.Logger
import inql.graphql.GQLSchema
import inql.graphql.GraphQLSchemaToSDL
import inql.graphql.Utils
import inql.scanner.ScanResult
import inql.scanner.SchemaDiscoverySource
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class HistorySchemaService(private val inql: InQL) {
    companion object {
        private const val DEBOUNCE_MS = 5000L
        private const val FIELDS_BEFORE_REFRESH = 10
        private const val YIELD_EVERY = 25
    }

    private data class HistoryEntry(
        val request: HttpRequest,
        val response: HttpResponse?,
    )

    private val hostSchemas = ConcurrentHashMap<String, GraphQLSchema>()
    private val hostSchemaSignatures = ConcurrentHashMap<String, String>()
    private val hostFieldCounts = ConcurrentHashMap<String, Int>()
    private val pendingFieldCounts = ConcurrentHashMap<String, AtomicInteger>()
    private val debounceJobs = ConcurrentHashMap<String, Job>()
    private val extractionJobs = ConcurrentHashMap<String, Job>()
    private val updateMutex = Mutex()
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    fun processRequestResponse(requestResponse: HttpRequestResponse) {
        processRequest(requestResponse.request(), requestResponse.response())
    }

    fun processRequest(request: HttpRequest, response: HttpResponse? = null) {
        if (!isTrackingEnabled()) return
        if (!Utils.isGraphQLRequest(request)) return
        if (!shouldProcessUrl(request.url())) return

        val host = HistoryHostKey.fromRequest(request)
        val existing = hostSchemas[host] ?: loadExistingHistorySchema(host)
        val operation = Utils.getGraphQLOperation(request) ?: return
        val responseBody = if (response != null && HistoryResponseValidator.isSuccessfulResponse(response)) {
            response.bodyToString()
        } else {
            null
        }
        val merged = HistorySchemaBuilder.buildFromOperation(operation, responseBody, existing) ?: return

        if (!applySchemaChange(host, merged, existing, request)) return
    }

    fun extractSchemaForHost(host: String) {
        val normalizedHost = HistoryHostKey.normalize(host)
        extractionJobs[normalizedHost]?.cancel()
        extractionJobs[normalizedHost] = serviceScope.launch(Dispatchers.IO) {
            try {
                runBulkExtraction(normalizedHost)
            } finally {
                extractionJobs.remove(normalizedHost)
            }
        }
    }

    fun stop() {
        extractionJobs.values.forEach { it.cancel() }
        extractionJobs.clear()
        debounceJobs.values.forEach { it.cancel() }
        debounceJobs.clear()
        serviceScope.cancel()
    }

    private suspend fun runBulkExtraction(filterHostKey: String) {
        val historyItems = collectHistoryForHost(filterHostKey)
        if (historyItems.isEmpty()) {
            Logger.info("No proxy history or site map entries found for host: $filterHostKey")
            return
        }

        val storageHostKey = HistoryHostKey.fromRequest(historyItems.first().request)
        Logger.info(
            "Extracting GraphQL schema from ${historyItems.size} history item(s) for $storageHostKey",
        )

        var merged: GraphQLSchema? = hostSchemas[storageHostKey] ?: loadExistingHistorySchema(storageHostKey)
        var requestTemplate: HttpRequest? = null
        var processed = 0

        for (item in historyItems) {
            if (processed % YIELD_EVERY == 0) {
                yield()
            }
            processed++

            val req = item.request
            if (!Utils.isGraphQLRequest(req)) continue
            if (!shouldProcessUrl(req.url())) continue

            val operation = Utils.getGraphQLOperation(req) ?: continue
            val responseBody = item.response
                ?.takeIf { HistoryResponseValidator.isSuccessfulResponse(it) }
                ?.bodyToString()

            val result = HistorySchemaBuilder.buildFromOperation(operation, responseBody, merged) ?: continue
            val newSignature = schemaSignature(result)
            val previousSignature = merged?.let { schemaSignature(it) }
            if (newSignature == previousSignature) continue

            merged = result
            requestTemplate = requestTemplate ?: req.withBody("")
        }

        if (merged == null || requestTemplate == null) return

        hostSchemas[storageHostKey] = merged
        hostSchemaSignatures[storageHostKey] = schemaSignature(merged)
        hostFieldCounts[storageHostKey] = countFields(merged)
        applySchemaUpdate(storageHostKey, merged, requestTemplate)
    }

    private fun collectHistoryForHost(filterHostKey: String): List<HistoryEntry> {
        val results = LinkedHashMap<String, HistoryEntry>()

        fun addEntry(request: HttpRequest, response: HttpResponse?) {
            if (!HistoryHostKey.matches(HistoryHostKey.fromRequest(request), filterHostKey)) return
            val key = "${request.method()}:${request.url()}:${request.bodyToString().hashCode()}"
            results.putIfAbsent(key, HistoryEntry(request, response))
        }

        for (item in Burp.Montoya.proxy().history()) {
            addEntry(item.finalRequest(), item.originalResponse())
        }

        for (item in Burp.Montoya.siteMap().requestResponses()) {
            addEntry(item.request(), item.response())
        }

        return results.values.toList()
    }

    private fun isTrackingEnabled(): Boolean {
        return Config.getInstance().getBoolean("history.tracking_enabled") == true
    }

    private fun shouldProcessUrl(url: String): Boolean {
        if (Config.getInstance().getBoolean("history.in_scope_only") == true) {
            return Burp.Montoya.scope().isInScope(url)
        }
        return true
    }

    private fun loadExistingHistorySchema(host: String): GraphQLSchema? {
        val tab = inql.scanner.findHistoryTabForHost(host) ?: return null
        val result = tab.scanResults.find { it.schemaDiscoverySource == SchemaDiscoverySource.HISTORY }
        return result?.parsedSchema?.schema
    }

    private fun applySchemaChange(
        host: String,
        merged: GraphQLSchema,
        existing: GraphQLSchema?,
        requestTemplate: HttpRequest,
    ): Boolean {
        val newSignature = schemaSignature(merged)
        val previousSignature = hostSchemaSignatures[host] ?: existing?.let { schemaSignature(it) }
        if (newSignature == previousSignature) return false

        hostSchemas[host] = merged
        hostSchemaSignatures[host] = newSignature
        val previousFieldCount = hostFieldCounts[host] ?: existing?.let { countFields(it) } ?: 0
        val newFieldCount = countFields(merged)
        hostFieldCounts[host] = newFieldCount
        scheduleUiUpdate(host, requestTemplate, newFieldCount - previousFieldCount)
        return true
    }

    private fun schemaSignature(schema: GraphQLSchema): String {
        return schema.typeMap.entries
            .sortedBy { it.key }
            .joinToString("\n") { (name, type) ->
                when (type) {
                    is GraphQLObjectType -> {
                        val fields = type.fieldDefinitions
                            .filter { it.name != "_inql_placeholder" }
                            .sortedBy { it.name }
                            .joinToString(",") { field -> "${field.name}:${field.type}" }
                        "$name{$fields}"
                    }
                    else -> name
                }
            }
    }

    private fun countFields(schema: GraphQLSchema): Int {
        return schema.typeMap.values
            .filterIsInstance<GraphQLObjectType>()
            .sumOf { type ->
                type.fieldDefinitions.count { it.name != "_inql_placeholder" }
            }
    }

    private fun scheduleUiUpdate(host: String, requestTemplate: HttpRequest, newFields: Int) {
        val counter = pendingFieldCounts.computeIfAbsent(host) { AtomicInteger(0) }
        if (newFields > 0) {
            counter.addAndGet(newFields)
        }

        if (counter.get() >= FIELDS_BEFORE_REFRESH) {
            debounceJobs[host]?.cancel()
            val schema = hostSchemas[host] ?: return
            applySchemaUpdate(host, schema, requestTemplate)
            counter.set(0)
            return
        }

        debounceJobs[host]?.cancel()
        debounceJobs[host] = serviceScope.launch {
            delay(DEBOUNCE_MS)
            val schema = hostSchemas[host] ?: return@launch
            applySchemaUpdate(host, schema, requestTemplate)
            counter.set(0)
        }
    }

    private fun applySchemaUpdate(
        host: String,
        schema: GraphQLSchema,
        requestTemplate: HttpRequest,
    ) {
        serviceScope.launch {
            updateMutex.withLock {
                try {
                    val sdl = withContext(Dispatchers.Default) {
                        GraphQLSchemaToSDL.schemaToSDL(schema)
                    }

                    withContext(Dispatchers.Main) {
                        val gqlSchema = GQLSchema(sdl)
                        val historyScanResult = ScanResult(
                            host,
                            requestTemplate,
                            gqlSchema,
                            jsonSchema = gqlSchema.jsonSchema,
                            sdlSchema = sdl,
                            schemaDiscoverySource = SchemaDiscoverySource.HISTORY,
                        )
                        inql.scanner.applyScanResult(
                            host,
                            SchemaDiscoverySource.HISTORY,
                            requestTemplate,
                            historyScanResult,
                            focus = false,
                        )
                    }
                } catch (e: Exception) {
                    Logger.error("Failed to apply history schema update for $host: ${e.message}")
                }
            }
        }
    }
}
