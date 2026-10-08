package inql.attacker

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import graphql.language.ArrayValue
import graphql.language.Field
import graphql.language.Node
import graphql.language.NodeTraverser
import graphql.language.NodeVisitorStub
import graphql.language.ObjectValue
import graphql.language.OperationDefinition
import graphql.language.ScalarValue
import graphql.language.SelectionSet
import graphql.language.Value
import graphql.language.VariableReference
import graphql.parser.Parser
import graphql.util.TraversalControl
import graphql.util.TraverserContext
import inql.graphql.GraphQLRequestPayload
import inql.graphql.GraphQLRequestTransformer
import inql.history.GraphQLTypeInference

data class VariableCollectResult(
    val variables: List<BatchVariable>,
    val payload: GraphQLRequestPayload?,
    val error: String? = null,
)

object BatchVariableCollector {
    private val parser = Parser()
    private val gson = Gson()
    private val queryVariablePattern = Regex("""\$([A-Za-z_][A-Za-z0-9_]*)""")

    /** Only the first elements of each list are offered as positions, to keep the variables list usable. */
    const val MAX_LIST_ELEMENTS = 100

    fun collect(request: HttpRequest): VariableCollectResult {
        return try {
            collectInternal(request)
        } catch (e: Exception) {
            VariableCollectResult(
                variables = emptyList(),
                payload = null,
                error = "Failed to read GraphQL variables: ${e.message}",
            )
        }
    }

    private fun collectInternal(request: HttpRequest): VariableCollectResult {
        val payload = GraphQLRequestTransformer.parsePayloadAnyMethod(request)
            ?: return VariableCollectResult(
                variables = emptyList(),
                payload = null,
                error = "Could not parse a GraphQL request. Ensure the request contains a valid query.",
            )
        val operation = payload.operations.first()
        val opDef = try {
            selectOperation(
                parser.parseDocument(operation.query).definitions.filterIsInstance<OperationDefinition>(),
                operation.operationName,
            )
        } catch (_: Exception) {
            null
        }

        val ordered = LinkedHashMap<String, BatchVariable>()
        fun add(variable: BatchVariable) {
            ordered.putIfAbsent(variable.key, variable)
        }

        opDef?.variableDefinitions?.forEach {
            add(BatchVariable(listOf(it.name), GraphQLTypeInference.typeToSdl(it.type)))
        }
        opDef?.let { collectVariableReferences(it) }?.forEach { add(BatchVariable(listOf(it))) }
        collectFromQueryText(operation.query).forEach { add(BatchVariable(listOf(it))) }

        val graphqlRoots = ordered.values.map { it.path.first() }.toSet()
        for (path in flattenJsonPaths(parseVariablesObject(operation.variables))) {
            if (graphqlRoots.isNotEmpty() && path.first() !in graphqlRoots) continue
            add(BatchVariable(path))
        }

        opDef?.let { collectRootFieldArguments(it.selectionSet) }?.forEach { add(it) }

        if (ordered.isEmpty()) {
            return VariableCollectResult(
                variables = emptyList(),
                payload = payload,
                error = "No GraphQL variables or arguments found in the query.",
            )
        }

        return VariableCollectResult(ordered.values.sortedWith { a, b -> comparePaths(a.path, b.path) }, payload)
    }

    fun selectOperation(
        operations: List<OperationDefinition>,
        operationName: String?,
    ): OperationDefinition? {
        if (operations.isEmpty()) return null
        if (operationName.isNullOrBlank()) return operations.first()
        return operations.firstOrNull { it.name == operationName } ?: operations.first()
    }

    /** Parses the request's variables; a JSON string holding the variables object is unwrapped. */
    fun parseVariablesObject(variables: String?): JsonObject {
        if (variables.isNullOrBlank()) return JsonObject()
        return try {
            var element = gson.fromJson(variables, JsonElement::class.java)
            if (element != null && element.isJsonPrimitive && element.asJsonPrimitive.isString) {
                element = gson.fromJson(element.asString, JsonElement::class.java)
            }
            if (element != null && element.isJsonObject) element.asJsonObject else JsonObject()
        } catch (_: Exception) {
            JsonObject()
        }
    }

    /** Every path in [obj], descending into nested objects and lists. List elements use `[index]` segments. */
    private fun flattenJsonPaths(obj: JsonObject, prefix: List<String> = emptyList()): List<List<String>> {
        val paths = ArrayList<List<String>>()
        for ((key, value) in obj.entrySet()) {
            val path = prefix + key
            paths.add(path)
            paths.addAll(flattenNested(value, path))
        }
        return paths
    }

    private fun flattenNested(value: JsonElement?, path: List<String>): List<List<String>> {
        return when {
            value == null -> emptyList()
            value.isJsonObject -> flattenJsonPaths(value.asJsonObject, path)
            value.isJsonArray -> value.asJsonArray.take(MAX_LIST_ELEMENTS).flatMapIndexed { index, element ->
                val elementPath = path + indexSegment(index)
                listOf(elementPath) + flattenNested(element, elementPath)
            }
            else -> emptyList()
        }
    }

    /** Returns a copy of [base] with each value stored at its path. */
    fun applyOverrides(base: JsonObject, overrides: Map<List<String>, JsonElement>): JsonObject {
        val copy = base.deepCopy()
        for ((path, value) in overrides) {
            copy.add(path[0], withValueAt(copy.get(path[0]), path.drop(1), value))
        }
        return copy
    }

    fun valueAtPath(obj: JsonObject, path: List<String>): JsonElement? {
        var current: JsonElement = obj
        for (segment in path) {
            val index = arrayIndex(segment)
            current = when {
                index != null && current.isJsonArray -> current.asJsonArray.takeIf { index < it.size() }?.get(index)
                index == null && current.isJsonObject -> current.asJsonObject.get(segment)
                else -> null
            } ?: return null
        }
        return current
    }

    /** Joins path segments into a key such as `input.searchContext[0].domain`. */
    fun joinPath(path: List<String>): String {
        val out = StringBuilder()
        for (segment in path) {
            if (out.isNotEmpty() && arrayIndex(segment) == null) out.append('.')
            out.append(segment)
        }
        return out.toString()
    }

    /** The name a field's result is returned under. */
    fun responseKey(field: Field): String = field.alias ?: field.name

    private fun indexSegment(index: Int): String = "[$index]"

    /** The list index of a `[index]` path segment, or null for object keys. */
    fun arrayIndex(segment: String): Int? {
        if (!segment.startsWith("[") || !segment.endsWith("]")) return null
        return segment.substring(1, segment.length - 1).toIntOrNull()
    }

    /** Orders paths segment by segment, comparing list indexes numerically so [2] comes before [10]. */
    private fun comparePaths(a: List<String>, b: List<String>): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val indexA = arrayIndex(a[i])
            val indexB = arrayIndex(b[i])
            val cmp = if (indexA != null && indexB != null) indexA.compareTo(indexB) else a[i].compareTo(b[i])
            if (cmp != 0) return cmp
        }
        return a.size.compareTo(b.size)
    }

    fun collectVariableReferences(node: Node<*>): Set<String> {
        val names = linkedSetOf<String>()
        try {
            NodeTraverser().preOrder(
                object : NodeVisitorStub() {
                    override fun visitVariableReference(
                        reference: VariableReference,
                        data: TraverserContext<Node<*>>,
                    ): TraversalControl {
                        names.add(reference.name)
                        return TraversalControl.CONTINUE
                    }
                },
                node,
            )
        } catch (_: Exception) {
            // Callers fall back to collectFromQueryText().
        }
        return names
    }

    fun collectFromQueryText(query: String): List<String> {
        if (query.isBlank()) return emptyList()
        return queryVariablePattern.findAll(query).map { it.groupValues[1] }.distinct().toList()
    }

    private fun collectRootFieldArguments(selectionSet: SelectionSet?): List<BatchVariable> {
        val out = ArrayList<BatchVariable>()
        if (selectionSet == null) return out
        for (selection in selectionSet.selections) {
            if (selection !is Field) continue
            for (argument in selection.arguments) {
                addArgumentTree(argument.value, listOf(responseKey(selection), argument.name), out)
            }
        }
        return out
    }

    private fun addArgumentTree(value: Value<*>, path: List<String>, out: MutableList<BatchVariable>) {
        if (value is VariableReference) return
        val type = if (value is ScalarValue<*>) GraphQLTypeInference.inferValueType(value, emptyMap()) else null
        out.add(BatchVariable(path, type, BatchVariableKind.ARGUMENT))
        if (value is ObjectValue) {
            for (field in value.objectFields) {
                addArgumentTree(field.value, path + field.name, out)
            }
        }
        if (value is ArrayValue) {
            value.values.take(MAX_LIST_ELEMENTS).forEachIndexed { index, element ->
                addArgumentTree(element, path + indexSegment(index), out)
            }
        }
    }

    /** Returns [container] with [value] stored at [path], creating objects and lists along the way as needed. */
    private fun withValueAt(container: JsonElement?, path: List<String>, value: JsonElement): JsonElement {
        if (path.isEmpty()) return value
        val segment = path.first()
        val index = arrayIndex(segment)
        if (index != null) {
            val array = if (container != null && container.isJsonArray) container.asJsonArray else JsonArray()
            while (array.size() <= index) array.add(JsonNull.INSTANCE)
            array.set(index, withValueAt(array.get(index), path.drop(1), value))
            return array
        }
        val obj = if (container != null && container.isJsonObject) container.asJsonObject else JsonObject()
        obj.add(segment, withValueAt(obj.get(segment), path.drop(1), value))
        return obj
    }
}
