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
import graphql.language.OperationDefinition
import graphql.language.SelectionSet
import graphql.language.VariableReference
import graphql.parser.Parser
import graphql.util.TraversalControl
import graphql.util.TraverserContext
import inql.graphql.GraphQLRequestPayload
import inql.graphql.GraphQLRequestTransformer
import inql.history.GraphQLTypeInference
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

data class VariableCollectResult(
    val variables: List<BatchVariable>,
    val payload: GraphQLRequestPayload?,
    val error: String? = null,
)

object BatchVariableCollector {
    private val parser = Parser()
    private val gson = Gson()
    private val queryVariablePattern = Regex("""\$([A-Za-z_][A-Za-z0-9_]*)""")
    private val indexPattern = Regex("""\[\d+]""")
    private val indexedPartPattern = Regex("""^(.*?)((?:\[\d+])+)$""")

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
        val extracted = extract(request)
        if (extracted.query.isNullOrBlank() && extracted.variables.isNullOrBlank()) {
            return VariableCollectResult(
                variables = emptyList(),
                payload = extracted.payload,
                error = extracted.error ?: "Could not parse a GraphQL request. Ensure the request contains a valid query.",
            )
        }

        val payload = extracted.payload ?: extracted.query?.let {
            GraphQLRequestPayload.single(it, extracted.variables, extracted.operationName)
        }

        val ordered = LinkedHashMap<String, BatchVariable>()
        val query = extracted.query.orEmpty()

        val document = if (query.isNotBlank()) {
            try {
                parser.parseDocument(query)
            } catch (_: Exception) {
                null
            }
        } else {
            null
        }

        val opDef = document?.let { doc ->
            selectOperation(
                doc.definitions.filterIsInstance<OperationDefinition>(),
                extracted.operationName,
            )
        }

        if (opDef != null) {
            for (def in opDef.variableDefinitions) {
                ordered[def.name] = BatchVariable(
                    path = listOf(def.name),
                    type = GraphQLTypeInference.typeToSdl(def.type),
                    kind = BatchVariableKind.VARIABLE,
                    graphqlVariable = def.name,
                    jsonPath = listOf(def.name),
                )
            }
            for (ref in collectVariableReferences(opDef)) {
                ordered.putIfAbsent(
                    ref,
                    BatchVariable(
                        path = listOf(ref),
                        kind = BatchVariableKind.VARIABLE,
                        graphqlVariable = ref,
                        jsonPath = listOf(ref),
                    ),
                )
            }
        }

        for (name in collectFromQueryText(query)) {
            ordered.putIfAbsent(
                name,
                BatchVariable(
                    path = listOf(name),
                    kind = BatchVariableKind.VARIABLE,
                    graphqlVariable = name,
                    jsonPath = listOf(name),
                ),
            )
        }

        if (document != null && opDef != null) {
            for (argument in collectRootFieldArguments(opDef.selectionSet)) {
                ordered.putIfAbsent(argument.key, argument)
            }
        }

        val variablesObject = parseVariablesObject(extracted.variables)
        val graphqlRoots = ordered.keys.toSet()
        for (path in flattenJsonPaths(variablesObject)) {
            if (graphqlRoots.isNotEmpty() && path.first() !in graphqlRoots) continue
            val key = joinPath(path)
            ordered.putIfAbsent(
                key,
                BatchVariable(
                    path = path,
                    type = ordered[key]?.type,
                    kind = BatchVariableKind.VARIABLE,
                    graphqlVariable = path.first(),
                    jsonPath = path,
                ),
            )
        }

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

    fun parseVariablesObject(variables: String?): JsonObject {
        if (variables.isNullOrBlank() || variables == "null") return JsonObject()
        return try {
            val element = gson.fromJson(variables, JsonElement::class.java)
            if (element != null && element.isJsonObject) element.asJsonObject else JsonObject()
        } catch (_: Exception) {
            JsonObject()
        }
    }

    /** Every path in [obj], descending into nested objects and lists. List elements use `[index]` segments. */
    fun flattenJsonPaths(obj: JsonObject, prefix: List<String> = emptyList()): List<List<String>> {
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

    fun applyOverrides(base: JsonObject, overrides: Map<String, JsonElement>): JsonObject {
        val copy = base.deepCopy()
        for ((key, value) in overrides) {
            if (value.isJsonNull) continue
            val path = splitPath(key)
            if (path.isNotEmpty()) setPath(copy, path, value)
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

    fun graphqlName(pathKey: String): String = splitPath(pathKey).firstOrNull() ?: pathKey

    /** Joins path segments into a key such as `input.searchContext[0].domain`. */
    fun joinPath(path: List<String>): String {
        val out = StringBuilder()
        for (segment in path) {
            if (out.isNotEmpty() && arrayIndex(segment) == null) out.append('.')
            out.append(segment)
        }
        return out.toString()
    }

    /** Inverse of [joinPath]. */
    fun splitPath(key: String): List<String> {
        val segments = ArrayList<String>()
        for (part in key.split('.')) {
            if (part.isEmpty()) continue
            // Trailing `[n][m]` suffixes are list indexes: `searchContext[0]` -> `searchContext`, `[0]`.
            val match = indexedPartPattern.matchEntire(part)
            if (match == null) {
                segments.add(part)
                continue
            }
            val name = match.groupValues[1]
            if (name.isNotEmpty()) segments.add(name)
            indexPattern.findAll(match.groupValues[2]).forEach { segments.add(it.value) }
        }
        return segments
    }

    private fun indexSegment(index: Int): String = "[$index]"

    private fun arrayIndex(segment: String): Int? {
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
            // Query-text regex in collectInternal() still finds $variables.
        }
        return names
    }

    fun collectFromQueryText(query: String): List<String> {
        if (query.isBlank()) return emptyList()
        return queryVariablePattern.findAll(query).map { it.groupValues[1] }.distinct().toList()
    }

    fun sanitizeName(parts: List<String>): String {
        val raw = parts.joinToString("_") { part ->
            part.replace(Regex("[^A-Za-z0-9_]"), "_").ifBlank { "arg" }
        }
        return if (raw.firstOrNull()?.isDigit() == true) "_$raw" else raw
    }

    private fun collectRootFieldArguments(selectionSet: SelectionSet?): List<BatchVariable> {
        val out = ArrayList<BatchVariable>()
        if (selectionSet == null) return out
        for (selection in selectionSet.selections) {
            if (selection !is Field) continue
            val path = listOf(selection.name)
            for (argument in selection.arguments) {
                addArgumentTree(argument.value, path + argument.name, path + argument.name, out)
            }
        }
        return out
    }

    private fun addArgumentTree(
        value: graphql.language.Value<*>,
        displayPath: List<String>,
        argumentRoot: List<String>,
        out: MutableList<BatchVariable>,
    ) {
        if (value is VariableReference) return
        val variableName = sanitizeName(argumentRoot)
        val nested = displayPath.drop(argumentRoot.size)
        out.add(
            BatchVariable(
                path = displayPath,
                type = inferLiteralType(value),
                kind = BatchVariableKind.ARGUMENT,
                graphqlVariable = variableName,
                jsonPath = listOf(variableName) + nested,
            ),
        )
        if (value is graphql.language.ObjectValue) {
            for (field in value.objectFields) {
                addArgumentTree(field.value, displayPath + field.name, argumentRoot, out)
            }
        }
        if (value is ArrayValue) {
            value.values.take(MAX_LIST_ELEMENTS).forEachIndexed { index, element ->
                addArgumentTree(element, displayPath + indexSegment(index), argumentRoot, out)
            }
        }
    }

    private fun inferLiteralType(value: graphql.language.Value<*>): String? {
        return when (value) {
            is graphql.language.StringValue -> "String"
            is graphql.language.IntValue -> "Int"
            is graphql.language.FloatValue -> "Float"
            is graphql.language.BooleanValue -> "Boolean"
            else -> null
        }
    }

    private fun setPath(obj: JsonObject, path: List<String>, value: JsonElement) {
        obj.add(path[0], withValueAt(obj.get(path[0]), path.drop(1), value))
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

    private data class Extracted(
        val query: String?,
        val variables: String?,
        val operationName: String?,
        val payload: GraphQLRequestPayload? = null,
        val error: String? = null,
    )

    private fun extract(request: HttpRequest): Extracted {
        GraphQLRequestTransformer.parsePayload(request)?.operations?.firstOrNull()?.let { operation ->
            return Extracted(operation.query, operation.variables, operation.operationName, GraphQLRequestPayload(listOf(operation)))
        }

        fromJsonBody(request.bodyToString())?.let { return it }
        fromGet(request)?.let { return it }

        val trimmed = request.bodyToString().trim().removePrefix("\uFEFF")
        if (looksLikeGraphQL(trimmed)) {
            return Extracted(trimmed, null, null)
        }

        return Extracted(null, null, null, error = "Could not parse a GraphQL request. Ensure the request contains a valid query.")
    }

    private fun fromJsonBody(body: String): Extracted? {
        val trimmed = body.trim().removePrefix("\uFEFF")
        if (trimmed.isEmpty()) return null
        val json = try {
            when {
                trimmed.startsWith("{") -> gson.fromJson(trimmed, JsonObject::class.java)
                trimmed.startsWith("[") -> {
                    val array = gson.fromJson(trimmed, com.google.gson.JsonArray::class.java)
                    array?.firstOrNull { it.isJsonObject }?.asJsonObject
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        } ?: return null

        val query = readJsonString(json, "query") ?: readJsonString(json, "mutation") ?: return null
        val variables = json.get("variables")?.takeUnless { it.isJsonNull }?.let { element ->
            if (element.isJsonPrimitive && element.asJsonPrimitive.isString) element.asString else element.toString()
        }
        val operationName = readJsonString(json, "operationName")
        return Extracted(query, variables, operationName)
    }

    private fun fromGet(request: HttpRequest): Extracted? {
        val queryString = rawQueryOf(request) ?: return null
        val params = parseQueryString(queryString)
        val queryDocument = params["query"] ?: return null
        val query = decode(queryDocument).trim()
        if (query.isEmpty()) return null
        val variables = params["variables"]?.let { decode(it) }
        val operationName = params["operationName"]?.let { decode(it) }?.takeIf { it.isNotBlank() }
        return Extracted(query, variables, operationName)
    }

    private fun rawQueryOf(request: HttpRequest): String? {
        val fromUrl = try {
            URI.create(request.url()).rawQuery
        } catch (_: Exception) {
            null
        }
        if (!fromUrl.isNullOrBlank()) return fromUrl
        val path = try {
            request.path()
        } catch (_: Exception) {
            null
        } ?: return null
        val idx = path.indexOf('?')
        if (idx == -1) return null
        return path.substring(idx + 1).takeIf { it.isNotBlank() }
    }

    private fun parseQueryString(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        return query.split('&').mapNotNull { part ->
            if (part.isBlank()) return@mapNotNull null
            val idx = part.indexOf('=')
            if (idx == -1) part to "" else part.substring(0, idx) to part.substring(idx + 1)
        }.toMap()
    }

    private fun decode(value: String): String {
        return try {
            URLDecoder.decode(value, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            value
        }
    }

    private fun readJsonString(json: JsonObject, field: String): String? {
        val element = json.get(field) ?: return null
        if (!element.isJsonPrimitive || !element.asJsonPrimitive.isString) return null
        return element.asString.trim().takeIf { it.isNotEmpty() }
    }

    private fun looksLikeGraphQL(document: String): Boolean {
        val trimmed = document.trimStart()
        return trimmed.startsWith("query", ignoreCase = true) ||
            trimmed.startsWith("mutation", ignoreCase = true) ||
            trimmed.startsWith("subscription", ignoreCase = true) ||
            trimmed.startsWith("{")
    }

}
