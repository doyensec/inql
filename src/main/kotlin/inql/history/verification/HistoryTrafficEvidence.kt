package inql.history.verification

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.language.*
import graphql.parser.Parser
import inql.Logger
import inql.bruteforcer.SampleValue
import inql.bruteforcer.chainKey
import inql.graphql.Utils
import inql.history.HistoryTraffic
import org.json.JSONArray
import org.json.JSONObject

internal class HistoryTrafficEvidence(
    val argumentSamples: Map<String, Map<String, SampleValue>>,
    val enumCandidates: Set<String>,
    val typeNames: Set<String>,
    val valueNames: Set<String>,
    val selectedFields: Map<String, Set<String>>,
    val argumentNames: Map<String, Set<String>>,
    val acceptedFields: Map<String, Set<String>>,
    val acceptedArguments: Map<String, Set<String>>,
    val typesAt: Map<String, Set<String>>,
) {
    companion object {
        private val ENUM_LIKE = Regex("^[A-Z][A-Z0-9_]*$")
        private const val MAX_ENUM_CANDIDATES = 5000
        private const val MAX_ENUM_LENGTH = 64

        fun collect(hostKey: String): HistoryTrafficEvidence {
            val collector = Collector()
            for (entry in HistoryTraffic.entriesForHost(hostKey)) {
                val responses = jsonObjects(entry.response?.bodyToString())
                operations(entry.request).forEachIndexed { i, operation ->
                    collector.add(operation, responses.getOrNull(i))
                }
            }
            return collector.result()
        }

        private fun operations(request: HttpRequest): List<RecordedOperation> {
            val body = request.bodyToString().trim()
            if (body.startsWith("[")) {
                val batch = jsonObjects(body)
                if (batch.isNotEmpty()) {
                    return batch.map { RecordedOperation(it.opt("query") as? String, it.optJSONObject("variables")?.toMap(), it.opt("operationName") as? String) }
                }
            }
            val operationName = jsonObjects(body).firstOrNull()?.opt("operationName") as? String
            return Utils.getGraphQLOperations(request).map { RecordedOperation(it.query, it.variables, operationName) }
        }

        private fun jsonObjects(body: String?): List<JSONObject> {
            val trimmed = body?.trim().orEmpty()
            return try {
                when {
                    trimmed.startsWith("[") -> JSONArray(trimmed).let { a -> (0 until a.length()).map { a.optJSONObject(it) ?: JSONObject() } }
                    trimmed.startsWith("{") -> listOf(JSONObject(trimmed))
                    else -> emptyList()
                }
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    private class RecordedOperation(val query: String?, val variables: Map<String, Any?>?, val name: String?)

    private class Operation(
        val type: String,
        val fragments: Map<String, FragmentDefinition>,
        val declaredTypes: Map<String, String>,
        val variables: Map<String, Any?>,
        val accepted: Boolean,
    )

    private class Collector {
        private val samples = linkedMapOf<String, MutableMap<String, SampleValue>>()
        private val enumCandidates = linkedSetOf<String>()
        private val typeNames = linkedSetOf<String>()
        private val valueNames = linkedSetOf<String>()
        private val selectedFields = linkedMapOf<String, MutableSet<String>>()
        private val argumentNames = linkedMapOf<String, MutableSet<String>>()
        private val acceptedFields = linkedMapOf<String, MutableSet<String>>()
        private val acceptedArguments = linkedMapOf<String, MutableSet<String>>()
        private val typesAt = linkedMapOf<String, MutableSet<String>>()
        private val parser = Parser()

        fun result() = HistoryTrafficEvidence(
            samples, enumCandidates, typeNames, valueNames, selectedFields, argumentNames, acceptedFields, acceptedArguments, typesAt,
        )

        fun add(recorded: RecordedOperation, response: JSONObject?) {
            val query = recorded.query?.let(Utils::normalizeGraphQLDocument) ?: return
            val document = try {
                parser.parseDocument(query)
            } catch (e: Exception) {
                Logger.debug("History verification: skipping an unparsable operation: ${e.message}")
                return
            }
            val definitions = document.definitions.filterIsInstance<OperationDefinition>()
            val definition = definitions.firstOrNull { it.name == recorded.name } ?: definitions.firstOrNull() ?: return
            val data = response?.opt("data") as? JSONObject
            collectStrings(recorded.variables, fromResponse = false)
            collectKeys(recorded.variables?.values)
            if (data != null) collectStrings(data, fromResponse = true)
            val operation = Operation(
                type = when (definition.operation) {
                    OperationDefinition.Operation.MUTATION -> "mutation"
                    OperationDefinition.Operation.SUBSCRIPTION -> "subscription"
                    else -> "query"
                },
                fragments = document.definitions.filterIsInstance<FragmentDefinition>().associateBy { it.name },
                declaredTypes = definition.variableDefinitions.associate { it.name to AstPrinter.printAst(it.type) },
                variables = recorded.variables.orEmpty(),
                accepted = data != null,
            )
            walk(definition.selectionSet, emptyList(), operation, mutableSetOf())
        }

        private fun walk(selectionSet: SelectionSet?, chain: List<String>, operation: Operation, spreading: MutableSet<String>) {
            val key = chainKey(operation.type, chain)
            for (selection in selectionSet?.selections.orEmpty()) {
                when (selection) {
                    is Field -> {
                        val fieldChain = chain + selection.name
                        val fieldKey = chainKey(operation.type, fieldChain)
                        if (!selection.name.startsWith("__")) {
                            selectedFields.getOrPut(key) { linkedSetOf() } += selection.name
                            if (operation.accepted) acceptedFields.getOrPut(key) { linkedSetOf() } += selection.name
                        }
                        for (argument in selection.arguments) {
                            valueNames += argument.name
                            argumentNames.getOrPut(fieldKey) { linkedSetOf() } += argument.name
                            collectEnumLiterals(argument.value)
                            if (!operation.accepted) continue
                            acceptedArguments.getOrPut(fieldKey) { linkedSetOf() } += argument.name
                            val sample = sampleOf(argument.value, operation) ?: continue
                            samples.getOrPut(fieldKey) { linkedMapOf() }.putIfAbsent(argument.name, sample)
                        }
                        walk(selection.selectionSet, fieldChain, operation, spreading)
                    }
                    is InlineFragment -> {
                        selection.typeCondition?.name?.let { addTypeAt(key, it) }
                        walk(selection.selectionSet, chain, operation, spreading)
                    }
                    is FragmentSpread -> {
                        val fragment = operation.fragments[selection.name] ?: continue
                        if (!spreading.add(fragment.name)) continue
                        fragment.typeCondition?.name?.let { addTypeAt(key, it) }
                        walk(fragment.selectionSet, chain, operation, spreading)
                        spreading.remove(fragment.name)
                    }
                }
            }
        }

        private fun addTypeAt(key: String, typeName: String) {
            typesAt.getOrPut(key) { linkedSetOf() } += typeName
            typeNames += typeName
        }

        private fun sampleOf(value: Value<*>, operation: Operation): SampleValue? {
            if (value is VariableReference) {
                val type = operation.declaredTypes[value.name] ?: return null
                if (!operation.variables.containsKey(value.name)) return null
                return SampleValue.Json(type, operation.variables[value.name])
            }
            if (containsVariable(value)) return null
            return SampleValue.Literal(AstPrinter.printAst(value))
        }

        private fun containsVariable(value: Value<*>): Boolean = when (value) {
            is VariableReference -> true
            is ArrayValue -> value.values.any(::containsVariable)
            is ObjectValue -> value.objectFields.any { containsVariable(it.value) }
            else -> false
        }

        private fun collectEnumLiterals(value: Value<*>) {
            when (value) {
                is EnumValue -> addEnumCandidate(value.name)
                is ArrayValue -> value.values.forEach(::collectEnumLiterals)
                is ObjectValue -> value.objectFields.forEach { valueNames += it.name; collectEnumLiterals(it.value) }
                else -> Unit
            }
        }

        private fun collectKeys(value: Any?) {
            when (value) {
                is Map<*, *> -> value.forEach { (k, v) -> (k as? String)?.let { valueNames += it }; collectKeys(v) }
                is JSONObject -> value.keySet().forEach { valueNames += it; collectKeys(value.opt(it)) }
                is Iterable<*> -> value.forEach(::collectKeys)
                is JSONArray -> (0 until value.length()).forEach { collectKeys(value.opt(it)) }
                else -> Unit
            }
        }

        private fun collectStrings(value: Any?, fromResponse: Boolean) {
            when (value) {
                is String -> if (ENUM_LIKE.matches(value) && value.length <= MAX_ENUM_LENGTH) addEnumCandidate(value)
                is JSONObject -> value.keySet().forEach { key ->
                    val child = value.opt(key)
                    if (fromResponse && key == "__typename" && child is String) typeNames += child else collectStrings(child, fromResponse)
                }
                is JSONArray -> (0 until value.length()).forEach { collectStrings(value.opt(it), fromResponse) }
                is Map<*, *> -> value.values.forEach { collectStrings(it, fromResponse) }
                is Iterable<*> -> value.forEach { collectStrings(it, fromResponse) }
                else -> Unit
            }
        }

        private fun addEnumCandidate(value: String) {
            if (enumCandidates.size < MAX_ENUM_CANDIDATES) enumCandidates += value
        }
    }
}
