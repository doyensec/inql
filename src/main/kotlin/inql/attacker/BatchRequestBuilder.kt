package inql.attacker

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import graphql.language.AstPrinter
import graphql.language.Document
import graphql.parser.Parser
import inql.graphql.GraphQLRequestContext
import inql.graphql.GraphQLRequestPayload
import inql.graphql.GraphQLRequestTransformer
import inql.graphql.GraphQLTransportFormat

sealed class BatchBuildResult {
    data class Success(val plan: BatchPlan) : BatchBuildResult()

    data class Failure(val message: String) : BatchBuildResult()
}

data class BatchChunk(
    val index: Int,
    val request: HttpRequest,
    val itemCount: Int,
    /** Per item, the payload sent to each position of [BatchPlan.variableLabels]; null where it was not changed. */
    val payloads: List<List<String?>>,
)

internal class PlannedItem(val payloads: List<String?>, val values: BatchItemValues)

/**
 * A validated batch attack. HTTP requests are built lazily, one chunk at a time, so large attacks
 * never hold every combination or request in memory at once.
 */
class BatchPlan internal constructor(
    val mode: BatchMode,
    val totalItems: Int,
    val requestCount: Int,
    val variableLabels: List<String>,
    private val chunks: Sequence<List<PlannedItem>>,
    private val buildChunk: (List<BatchItemValues>) -> HttpRequest,
) {
    /** Builds each HTTP request on demand. Throws [BatchBuildException] if a request cannot be built. */
    fun requests(): Sequence<BatchChunk> = chunks.mapIndexed { index, items ->
        BatchChunk(index, buildChunk(items.map { it.values }), items.size, items.map { it.payloads })
    }
}

class BatchBuildException(message: String) : Exception(message)

object BatchRequestBuilder {
    private val gson = GsonBuilder().disableHtmlEscaping().create()

    /** Upper bound for the number of batched operations in a whole attack. */
    const val MAX_TOTAL_ITEMS = 1_000_000

    /** Upper bound for the number of batched operations in a single HTTP request. */
    const val MAX_ITEMS_PER_REQUEST = 100_000

    fun build(request: HttpRequest, url: String, config: BatchAttackConfig): BatchBuildResult {
        if (config.selectedVariables.isEmpty()) {
            return BatchBuildResult.Failure("Select at least one variable to batch.")
        }

        val collected = BatchVariableCollector.collect(request)
        val payload = collected.payload
            ?: return BatchBuildResult.Failure(collected.error ?: "Could not parse a GraphQL request.")
        val variablesByKey = collected.variables.associateBy { it.key }
        val missing = config.selectedVariables.filter { it !in variablesByKey }
        if (missing.isNotEmpty()) {
            return BatchBuildResult.Failure(
                "Selected variable(s) ${missing.joinToString()} are not in the current request. " +
                    "Click Refresh and try again.",
            )
        }
        val selectedMeta = config.selectedVariables.map { variablesByKey.getValue(it) }

        val payloadSets: List<PayloadSetConfig>
        val loaded: List<List<JsonElement>>
        try {
            payloadSets = payloadSetsFor(config)
            loaded = loadPayloads(payloadSets, selectedMeta, config.usesSharedPayload())
        } catch (e: PayloadSourceException) {
            return BatchBuildResult.Failure(e.message ?: "Failed to load payloads.")
        }
        if (loaded.any { it.isEmpty() }) {
            return BatchBuildResult.Failure(
                "No payloads loaded. Check the payload source.",
            )
        }

        val attackType = config.effectiveAttackType
        val totalItems = estimateItemCount(
            attackType,
            config.selectedVariables.size,
            loaded.map { it.size.toLong() },
        )
        if (totalItems <= 0L) {
            return BatchBuildResult.Failure("No payload combinations were generated.")
        }
        if (totalItems > MAX_TOTAL_ITEMS) {
            return BatchBuildResult.Failure(
                "The attack would generate ${formatCount(totalItems)} items, which is more than the limit of " +
                    "${formatCount(MAX_TOTAL_ITEMS.toLong())}. Use fewer payloads or a different attack type.",
            )
        }
        val chunkSize = if (config.batchSize > 0) config.batchSize else totalItems.toInt()
        if (chunkSize > MAX_ITEMS_PER_REQUEST) {
            return BatchBuildResult.Failure(
                "A single request would contain ${formatCount(chunkSize.toLong())} items, which is more than the " +
                    "limit of ${formatCount(MAX_ITEMS_PER_REQUEST.toLong())}. Set a smaller \"Items per request\" value.",
            )
        }

        val template = payload.operations.first()
        val baseVariables = BatchVariableCollector.parseVariablesObject(template.variables)
        // Array batching repeats the whole query per item, so argument payloads are inlined into a parsed copy.
        val templateDocument: Document? = if (selectedMeta.any { it.kind == BatchVariableKind.ARGUMENT }) {
            try {
                Parser().parseDocument(template.query)
            } catch (e: Exception) {
                return BatchBuildResult.Failure("Failed to parse the GraphQL query: ${e.message}")
            }
        } else {
            null
        }
        val service = try {
            HttpService.httpService(url)
        } catch (e: Exception) {
            return BatchBuildResult.Failure("Invalid target URL: ${e.message}")
        }

        // For "Send as: Auto" sets, values from the original request hint at the JSON type each position expects.
        // Argument literals have no JSON value; their inferred scalar type is the hint.
        val coercionTargets = selectedMeta.filterIndexed { index, _ ->
            payloadSets[if (config.usesSharedPayload()) 0 else index].valueType == PayloadValueType.AUTO
        }.associate { meta ->
            val original = if (meta.kind == BatchVariableKind.VARIABLE) {
                BatchVariableCollector.valueAtPath(baseVariables, meta.path)
            } else {
                null
            }
            meta.key to Pair(meta.type, original)
        }

        val chunks = generateCombinations(attackType, config.selectedVariables, loaded)
            .map { combo ->
                combo.mapValues { (key, value) ->
                    val (type, original) = coercionTargets[key] ?: return@mapValues value
                    PayloadTypeCoercion.coerce(value, type, original)
                }
            }
            .map { combo ->
                PlannedItem(
                    payloads = config.selectedVariables.map { key -> combo[key]?.let(::displayPayload) },
                    values = itemValues(combo, variablesByKey),
                )
            }
            .chunked(chunkSize)

        val buildChunk = { items: List<BatchItemValues> ->
            try {
                when (config.mode) {
                    BatchMode.ARRAY -> {
                        val body = buildArrayBody(template, templateDocument, baseVariables, items)
                        GraphQLRequestTransformer.applyRawJsonBody(request, body)
                    }
                    BatchMode.ALIAS -> {
                        val batchedPayload = buildAliasPayload(template, baseVariables, items)
                        val context = requestContextFor(request, batchedPayload)
                        GraphQLRequestTransformer.applyPayload(request, batchedPayload, context)
                    }
                }.withService(service)
            } catch (e: AliasBatchException) {
                throw BatchBuildException(e.message ?: "Failed to rewrite the query for alias batching.")
            } catch (e: Exception) {
                throw BatchBuildException("Failed to build the batched request: ${e.message}")
            }
        }

        return BatchBuildResult.Success(
            BatchPlan(
                config.mode,
                totalItems.toInt(),
                requestCount(totalItems, config.batchSize).toInt(),
                selectedMeta.map { it.key },
                chunks,
                buildChunk,
            ),
        )
    }

    fun requestCount(itemCount: Long, batchSize: Int): Long {
        if (itemCount <= 0L) return 0
        if (batchSize <= 0 || itemCount == Long.MAX_VALUE) return 1
        return (itemCount + batchSize - 1) / batchSize
    }

    /** Formats a count for display; [Long.MAX_VALUE] stands for an overflowed count. */
    fun formatCount(count: Long): String = if (count == Long.MAX_VALUE) "too large" else "%,d".format(count)

    /** Null payloads keep the original value, so they have nothing to display. */
    private fun displayPayload(value: JsonElement): String? = when {
        value.isJsonNull -> null
        value.isJsonPrimitive -> value.asString
        else -> value.toString()
    }

    fun estimateItemCount(
        type: IntruderAttackType,
        positionCount: Int,
        payloadCounts: List<Long>,
    ): Long {
        if (positionCount <= 0 || payloadCounts.isEmpty() || payloadCounts.any { it <= 0L }) return 0
        if (positionCount == 1) return payloadCounts.first()
        return when (type) {
            IntruderAttackType.SNIPER -> saturatingMul(payloadCounts.first(), positionCount.toLong())
            IntruderAttackType.BATTERING_RAM -> payloadCounts.first()
            IntruderAttackType.PITCHFORK -> payloadCounts.minOrNull() ?: 0L
            IntruderAttackType.CLUSTER_BOMB -> payloadCounts.fold(1L) { acc, n -> saturatingMul(acc, n) }
        }
    }

    private fun saturatingMul(a: Long, b: Long): Long {
        if (a == 0L || b == 0L) return 0
        if (a > Long.MAX_VALUE / b) return Long.MAX_VALUE
        return a * b
    }

    internal fun generateCombinations(
        type: IntruderAttackType,
        positions: List<String>,
        payloads: List<List<JsonElement>>,
    ): Sequence<Map<String, JsonElement>> {
        if (positions.isEmpty() || payloads.isEmpty()) return emptySequence()
        if (positions.size == 1) {
            return payloads.first().asSequence().map { value -> mapOf(positions.first() to value) }
        }

        return when (type) {
            IntruderAttackType.SNIPER -> {
                val values = payloads.first()
                positions.asSequence().flatMap { position ->
                    values.asSequence().map { value -> mapOf(position to value) }
                }
            }

            IntruderAttackType.BATTERING_RAM -> {
                payloads.first().asSequence().map { value -> positions.associateWith { value } }
            }

            IntruderAttackType.PITCHFORK -> {
                val len = payloads.minOf { it.size }
                (0 until len).asSequence().map { index ->
                    positions.indices.associate { idx -> positions[idx] to payloads[idx][index] }
                }
            }

            IntruderAttackType.CLUSTER_BOMB -> cartesian(positions, payloads)
        }
    }

    private fun cartesian(
        positions: List<String>,
        payloads: List<List<JsonElement>>,
    ): Sequence<Map<String, JsonElement>> {
        if (payloads.any { it.isEmpty() }) return emptySequence()
        return sequence {
            // Odometer over payload indices; the last position changes fastest.
            val indices = IntArray(payloads.size)
            while (true) {
                yield(positions.indices.associate { idx -> positions[idx] to payloads[idx][indices[idx]] })
                var depth = payloads.size - 1
                while (depth >= 0) {
                    indices[depth]++
                    if (indices[depth] < payloads[depth].size) break
                    indices[depth] = 0
                    depth--
                }
                if (depth < 0) break
            }
        }
    }

    /** One payload set when all positions share it, otherwise one per selected variable, in order. */
    private fun payloadSetsFor(config: BatchAttackConfig): List<PayloadSetConfig> {
        if (config.usesSharedPayload()) {
            return listOf(config.sharedSource ?: throw PayloadSourceException("Choose a payload source."))
        }
        return config.selectedVariables.map { name ->
            config.perVariableSources[name] ?: throw PayloadSourceException("Set a payload source for $name.")
        }
    }

    /**
     * Loads every payload set and converts it to its "Send as" type. Payloads that are not valid values of that
     * type stop the attack before anything is sent.
     */
    private fun loadPayloads(
        payloadSets: List<PayloadSetConfig>,
        selectedMeta: List<BatchVariable>,
        shared: Boolean,
    ): List<List<JsonElement>> {
        return payloadSets.mapIndexed { index, set ->
            val values = PayloadSource.load(set.source)
            if (set.valueType == PayloadValueType.AUTO) return@mapIndexed values
            val invalid = ArrayList<String>()
            val converted = values.map { value ->
                set.valueType.convert(value) ?: value.also { invalid.add(if (it.isJsonPrimitive) it.asString else it.toString()) }
            }
            if (invalid.isNotEmpty()) {
                val target = if (shared) "the payload set" else selectedMeta[index].key
                val more = if (invalid.size > 1) " (and ${invalid.size - 1} more)" else ""
                throw PayloadSourceException(
                    "Payload \"${invalid.first()}\"$more is not a valid ${set.valueType.label} for $target. " +
                        "Fix the payloads or change \"Send as\".",
                )
            }
            converted
        }
    }

    /** Splits an item's payloads into variable and argument values. Null payloads keep the original value. */
    private fun itemValues(
        combo: Map<String, JsonElement>,
        variablesByKey: Map<String, BatchVariable>,
    ): BatchItemValues {
        val variables = LinkedHashMap<List<String>, JsonElement>()
        val arguments = LinkedHashMap<List<String>, JsonElement>()
        for ((key, value) in combo) {
            if (value.isJsonNull) continue
            val variable = variablesByKey.getValue(key)
            val target = if (variable.kind == BatchVariableKind.ARGUMENT) arguments else variables
            target[variable.path] = value
        }
        return BatchItemValues(variables, arguments)
    }

    private fun buildArrayBody(
        template: GraphQLRequestPayload.Operation,
        templateDocument: Document?,
        baseVariables: JsonObject,
        items: List<BatchItemValues>,
    ): String {
        val array = JsonArray()
        for (item in items) {
            val query = if (templateDocument == null || item.arguments.isEmpty()) {
                template.query
            } else {
                AstPrinter.printAst(ArgumentInliner.inline(templateDocument, template.operationName, item.arguments))
            }
            val entry = JsonObject()
            entry.addProperty("query", query)
            template.operationName?.let { entry.addProperty("operationName", it) }
            entry.add("variables", BatchVariableCollector.applyOverrides(baseVariables, item.variables))
            array.add(entry)
        }
        return gson.toJson(array)
    }

    private fun buildAliasPayload(
        template: GraphQLRequestPayload.Operation,
        baseVariables: JsonObject,
        items: List<BatchItemValues>,
    ): GraphQLRequestPayload {
        val (query, variables) = AliasBatchRewriter.rewrite(
            query = template.query,
            operationName = template.operationName,
            items = items,
            baseVariables = baseVariables,
        )
        return GraphQLRequestPayload.single(
            query = query,
            variables = variables.takeIf { it.size() > 0 }?.let { gson.toJson(it) },
            operationName = template.operationName,
        )
    }

    private fun requestContextFor(
        request: HttpRequest,
        payload: GraphQLRequestPayload,
    ): GraphQLRequestContext {
        val detected = GraphQLRequestTransformer.detectRequestContext(request)
        val hasVariables = payload.variables != null
        if (hasVariables && detected.format == GraphQLTransportFormat.RAW_GRAPHQL) {
            return GraphQLRequestContext(GraphQLTransportFormat.JSON)
        }
        return detected
    }
}
