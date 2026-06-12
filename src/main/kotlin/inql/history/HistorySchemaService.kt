package inql.history

import burp.Burp
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import graphql.schema.GraphQLSchema
import inql.Config
import inql.InQL
import inql.Logger
import inql.graphql.GQLSchema
import inql.graphql.Utils
import inql.scanner.ScanResult
import inql.scanner.SchemaDiscoverySource
import inql.schema.corrections.SchemaCorrections
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class HistorySchemaService(private val inql: InQL) {
    companion object {
        private const val DEBOUNCE_MS = 5000L
        private const val FIELDS_BEFORE_REFRESH = 10
        private const val YIELD_EVERY = 25
        private const val MAX_FINGERPRINTS_PER_HOST = 2000
    }

    private data class HistoryEntry(
        val request: HttpRequest,
        val response: HttpResponse?,
    )

    private data class HostState(
        val registry: SdlTypeRegistry,
        var corrections: SchemaCorrections,
        var requestTemplate: HttpRequest?,
        var snapshot: SdlTypeRegistry.Snapshot,
        var lastAppliedSnapshot: SdlTypeRegistry.Snapshot? = null,
    )

    private val hostStates = ConcurrentHashMap<String, HostState>()
    private val hostMutexes = ConcurrentHashMap<String, Mutex>()
    private val recentFingerprints = ConcurrentHashMap<String, MutableSet<String>>()
    private val pendingFieldCounts = ConcurrentHashMap<String, AtomicInteger>()
    private val debounceJobs = ConcurrentHashMap<String, Job>()
    private val extractionJobs = ConcurrentHashMap<String, Job>()
    private val updateMutex = Mutex()
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    fun processRequestResponse(requestResponse: HttpRequestResponse) {
        serviceScope.launch {
            processRequest(requestResponse.request(), requestResponse.response())
        }
    }

    suspend fun processRequest(request: HttpRequest, response: HttpResponse? = null) {
        if (!isTrackingEnabled()) return
        if (!shouldProcessUrl(request.url())) return

        val host = HistoryHostKey.fromRequest(request)
        val fingerprint = requestFingerprint(request)
        if (isDuplicate(host, fingerprint)) return

        val operations = Utils.getGraphQLOperations(request)
        if (operations.isEmpty()) return

        val responseBody = response?.bodyToString()
        val responseStatusCode = response?.statusCode()?.toInt()

        val mutex = hostMutexes.computeIfAbsent(host) { Mutex() }
        mutex.withLock {
            val state = getOrCreateHostState(host)
            var changed = false
            for (operation in operations) {
                if (HistorySchemaBuilder.mergeOperationIntoRegistry(
                        state.registry,
                        operation,
                        responseBody,
                        responseStatusCode,
                    )
                ) {
                    changed = true
                }
            }
            if (!changed) return

            state.requestTemplate = request.withBody("")
            val newSnapshot = state.registry.snapshot()
            val newFields = (newSnapshot.outputFields - state.snapshot.outputFields).coerceAtLeast(0)
            state.snapshot = newSnapshot
            scheduleUiUpdate(host, state, newFields)
        }
    }

    fun extractSchemaForHost(host: String, freshStart: Boolean = false) {
        val normalizedHost = HistoryHostKey.normalize(host)
        extractionJobs[normalizedHost]?.cancel()
        extractionJobs[normalizedHost] = serviceScope.launch(Dispatchers.IO) {
            try {
                runBulkExtraction(normalizedHost, freshStart)
            } finally {
                extractionJobs.remove(normalizedHost)
            }
        }
    }

    fun resetHostForReextract(host: String) {
        val normalizedHost = HistoryHostKey.normalize(host)
        clearHostState(normalizedHost)
        extractSchemaForHost(host, freshStart = true)
    }

    fun stop() {
        extractionJobs.values.forEach { it.cancel() }
        extractionJobs.clear()
        debounceJobs.values.forEach { it.cancel() }
        debounceJobs.clear()
        hostStates.clear()
        hostMutexes.clear()
        recentFingerprints.clear()
        serviceScope.cancel()
    }

    fun releaseHost(host: String) {
        val normalized = HistoryHostKey.normalize(host)
        clearHostState(normalized)
    }

    fun releaseHostIfNoOpenTabs(host: String) {
        val normalized = HistoryHostKey.normalize(host)
        val stillOpen = inql.scanner.getScannerTabs().any { tab ->
            inql.scanner.tabReferencesHost(tab, normalized)
        }
        if (!stillOpen) {
            releaseHost(normalized)
        }
    }

    fun storeCorrections(host: String, corrections: SchemaCorrections, schema: GraphQLSchema) {
        val normalized = HistoryHostKey.normalize(host)
        val registry = HistorySchemaBuilder.registryFromSchema(schema, corrections)
        hostStates[normalized] = HostState(
            registry = registry,
            corrections = corrections,
            requestTemplate = hostStates[normalized]?.requestTemplate,
            snapshot = registry.snapshot(),
        )
    }

    private suspend fun runBulkExtraction(filterHostKey: String, freshStart: Boolean = false) {
        val historyItems = collectHistoryForHost(filterHostKey)
        if (historyItems.isEmpty()) {
            Logger.info("No proxy history or site map entries found for host: $filterHostKey")
            return
        }

        val storageHostKey = HistoryHostKey.fromRequest(historyItems.first().request)
        Logger.info(
            "Extracting GraphQL schema from ${historyItems.size} history item(s) for $storageHostKey",
        )

        val tabMissing = inql.scanner.findHistoryTabForHost(storageHostKey) == null
        val mutex = hostMutexes.computeIfAbsent(storageHostKey) { Mutex() }
        mutex.withLock {
            if (freshStart) {
                clearHostState(storageHostKey)
            }
            val state = getOrCreateHostState(storageHostKey)
            var processed = 0

            for (item in historyItems) {
                if (processed % YIELD_EVERY == 0) {
                    yield()
                }
                processed++

                val req = item.request
                if (!Utils.isGraphQLRequest(req)) continue
                if (!shouldProcessUrl(req.url())) continue
                if (state.requestTemplate == null) {
                    state.requestTemplate = req.withBody("")
                }

                val operations = Utils.getGraphQLOperations(req)
                if (operations.isEmpty()) continue
                val responseBody = item.response?.bodyToString()
                val responseStatusCode = item.response?.statusCode()?.toInt()

                for (operation in operations) {
                    HistorySchemaBuilder.mergeOperationIntoRegistry(
                        state.registry,
                        operation,
                        responseBody,
                        responseStatusCode,
                    )
                }
            }

            state.snapshot = state.registry.snapshot()
            val requestTemplate = state.requestTemplate
            if (requestTemplate == null) {
                Logger.info("No valid GraphQL requests found in history for $storageHostKey")
                return
            }
            if (state.snapshot.outputFields == 0) {
                Logger.info("No schema could be built from history for $storageHostKey")
                return
            }

            applySchemaUpdate(storageHostKey, state, requestTemplate, focus = tabMissing)
        }
    }

    private fun collectHistoryForHost(filterHostKey: String): List<HistoryEntry> {
        val results = LinkedHashMap<String, HistoryEntry>()

        fun addEntry(request: HttpRequest, response: HttpResponse?) {
            if (!HistoryHostKey.matches(HistoryHostKey.fromRequest(request), filterHostKey)) return
            val key = requestFingerprint(request)
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

    private fun getOrCreateHostState(host: String): HostState {
        hostStates[host]?.let { return it }

        val corrections = loadCorrectionsForHost(host)
        val existing = loadExistingHistorySchema(host)
        val registry = if (existing != null) {
            HistorySchemaBuilder.registryFromSchema(existing, corrections)
        } else {
            val empty = SdlTypeRegistry()
            empty.setTypeAliases(corrections.typeAliasMap())
            if (corrections.hasActiveCorrections()) {
                empty.applyCorrections(corrections)
            }
            empty
        }
        return HostState(
            registry = registry,
            corrections = corrections,
            requestTemplate = null,
            snapshot = registry.snapshot(),
        ).also { hostStates[host] = it }
    }

    private fun clearHostState(host: String) {
        hostStates.remove(host)
        hostMutexes.remove(host)
        recentFingerprints.remove(host)
        pendingFieldCounts.remove(host)
        debounceJobs[host]?.cancel()
        debounceJobs.remove(host)
        extractionJobs[host]?.cancel()
        extractionJobs.remove(host)
    }

    private fun requestFingerprint(request: HttpRequest): String {
        return "${request.method()}:${request.url()}:${request.bodyToString().hashCode()}"
    }

    private fun isDuplicate(host: String, fingerprint: String): Boolean {
        val set = recentFingerprints.computeIfAbsent(host) {
            Collections.synchronizedSet(LinkedHashSet())
        }
        synchronized(set) {
            if (fingerprint in set) return true
            set.add(fingerprint)
            if (set.size > MAX_FINGERPRINTS_PER_HOST) {
                set.clear()
            }
            return false
        }
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

    private fun loadCorrectionsForHost(host: String): SchemaCorrections {
        val tab = inql.scanner.findHistoryTabForHost(host) ?: return SchemaCorrections.EMPTY
        val result = tab.scanResults.find { it.schemaDiscoverySource == SchemaDiscoverySource.HISTORY }
        return result?.schemaCorrections ?: SchemaCorrections.EMPTY
    }

    private fun scheduleUiUpdate(host: String, state: HostState, newFields: Int) {
        val requestTemplate = state.requestTemplate ?: return
        val counter = pendingFieldCounts.computeIfAbsent(host) { AtomicInteger(0) }
        if (newFields > 0) {
            counter.addAndGet(newFields)
        }

        if (counter.get() >= FIELDS_BEFORE_REFRESH) {
            debounceJobs[host]?.cancel()
            serviceScope.launch {
                val latest = hostStates[host] ?: return@launch
                val template = latest.requestTemplate ?: return@launch
                applySchemaUpdate(host, latest, template)
            }
            counter.set(0)
            return
        }

        debounceJobs[host]?.cancel()
        debounceJobs[host] = serviceScope.launch {
            delay(DEBOUNCE_MS)
            val latest = hostStates[host] ?: return@launch
            val template = latest.requestTemplate ?: return@launch
            applySchemaUpdate(host, latest, template)
            counter.set(0)
        }
    }

    private suspend fun applySchemaUpdate(
        host: String,
        state: HostState,
        requestTemplate: HttpRequest,
        focus: Boolean = false,
    ) {
        updateMutex.withLock {
            try {
                val latest = hostStates[host] ?: state
                if (latest.lastAppliedSnapshot == latest.snapshot) return

                val effectiveCorrections = latest.corrections
                val schema = withContext(Dispatchers.Default) {
                    HistorySchemaBuilder.finalizeRegistry(latest.registry, effectiveCorrections)
                } ?: return

                val hadHistoryResult = inql.scanner.findHistoryTabForHost(host)
                    ?.scanResults
                    ?.any { it.schemaDiscoverySource == SchemaDiscoverySource.HISTORY } == true

                withContext(Dispatchers.Main) {
                    val gqlSchema = GQLSchema(schema)
                    val historyScanResult = ScanResult(
                        host,
                        requestTemplate,
                        gqlSchema,
                        sdlSchema = gqlSchema.sdlSchema,
                        schemaDiscoverySource = SchemaDiscoverySource.HISTORY,
                        schemaCorrections = effectiveCorrections,
                    )
                    inql.scanner.applyScanResult(
                        host,
                        SchemaDiscoverySource.HISTORY,
                        requestTemplate,
                        historyScanResult,
                        focus = focus,
                        incrementalTreeUpdate = hadHistoryResult && !focus,
                    )
                    latest.lastAppliedSnapshot = latest.snapshot
                }
            } catch (e: Exception) {
                Logger.error("Failed to apply history schema update for $host: ${e.message}")
            }
        }
    }
}
