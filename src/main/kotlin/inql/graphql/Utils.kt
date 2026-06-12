package inql.graphql

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import graphql.schema.GraphQLModifiedType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLType
import inql.utils.get
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

data class GraphQLOperation(
    val query: String,
    val operationType: String = "query",
    val variables: Map<String, Any?>? = null,
)

object Utils {
    private val gson = Gson() // Initialize once
    private val jsonGraphQLEnvelopePattern = Regex(
        """^\{\s*"(?:query|mutation|operationName)"\s*:""",
        RegexOption.IGNORE_CASE,
    )
    private val shorthandSelectionSetPattern = Regex("""^\{\s*(?:__)?[A-Za-z_][A-Za-z0-9_]*""")

    /**
     * Ensures a GraphQL document string is not a raw JSON request envelope.
     */
    fun normalizeGraphQLDocument(input: String): String {
        val trimmed = stripBom(input.trim())
        if (!looksLikeJsonGraphQLEnvelope(trimmed)) return trimmed
        return extractQueryDocumentFromJson(trimmed) ?: trimmed
    }

    fun isGraphQLDocument(document: String): Boolean {
        return looksLikeGraphQLDocument(stripBom(document.trim()))
    }

    fun getGraphQLOperations(request: HttpRequest): List<GraphQLOperation> {
        return try {
            when (request.method().uppercase()) {
                "POST" -> getGraphQLOperationsFromPost(request)
                "GET" -> getGraphQLOperationFromGet(request)?.let { listOf(it) } ?: emptyList()
                else -> emptyList()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun getGraphQLOperation(request: HttpRequest): GraphQLOperation? {
        return getGraphQLOperations(request).firstOrNull()
    }

    private fun getGraphQLOperationsFromPost(request: HttpRequest): List<GraphQLOperation> {
        val body = request.bodyToString()
        if (body.isBlank()) return emptyList()

        val contentType = request.headers().get("content-type")
            ?.lowercase()
            ?.substringBefore(';')
            ?.trim()

        when (contentType) {
            "application/graphql" -> {
                return toGraphQLOperation(stripBom(body.trim()))?.let { listOf(it) } ?: emptyList()
            }
            "application/x-www-form-urlencoded" -> {
                return parseFormUrlEncodedBody(body)?.let { listOf(it) } ?: emptyList()
            }
            "application/json" -> {
                return parseJsonGraphQLBodies(body)
            }
        }

        // JSON envelope or raw document — do not require a specific URL path or Content-Type.
        val fromJson = parseJsonGraphQLBodies(body)
        if (fromJson.isNotEmpty()) return fromJson

        val trimmed = stripBom(body.trim())
        if (looksLikeJsonGraphQLEnvelope(trimmed)) {
            val query = extractQueryDocumentFromJson(trimmed) ?: return emptyList()
            return toGraphQLOperation(query)?.let { listOf(it) } ?: emptyList()
        }
        return toGraphQLOperation(trimmed)?.let { listOf(it) } ?: emptyList()
    }

    private fun getGraphQLOperationFromGet(request: HttpRequest): GraphQLOperation? {
        val uri = URI.create(request.url())
        val params = parseQueryString(uri.rawQuery ?: return null)
        val queryDocument = params["query"] ?: return null
        val decoded = URLDecoder.decode(queryDocument, StandardCharsets.UTF_8).trim()
        return toGraphQLOperation(decoded)
    }

    private fun parseJsonGraphQLBodies(body: String): List<GraphQLOperation> {
        val trimmed = stripBom(body.trim())
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return emptyList()
        if (!looksLikeJsonGraphQLEnvelope(trimmed) && !trimmed.startsWith("[")) return emptyList()

        if (trimmed.startsWith("[")) {
            return try {
                parseJsonGraphQLArray(gson.fromJson(trimmed, JsonArray::class.java))
            } catch (_: Exception) {
                parseJsonGraphQLBodiesWithOrgJson(trimmed)
            }
        }

        return try {
            val jsonObject = gson.fromJson(trimmed, JsonObject::class.java) ?: return emptyList()
            parseJsonGraphQLObject(jsonObject)?.let { listOf(it) }
                ?: extractQueryDocumentFromJson(trimmed)?.let { query ->
                    toGraphQLOperation(query)?.let { listOf(it) }
                }
                ?: emptyList()
        } catch (_: Exception) {
            extractQueryDocumentFromJson(trimmed)?.let { query ->
                toGraphQLOperation(query)?.let { listOf(it) }
            } ?: emptyList()
        }
    }

    private fun parseJsonGraphQLArray(array: JsonArray?): List<GraphQLOperation> {
        if (array == null) return emptyList()
        val operations = mutableListOf<GraphQLOperation>()
        val seenQueries = linkedSetOf<String>()
        for (element in array) {
            if (!element.isJsonObject) continue
            val operation = parseJsonGraphQLObject(element.asJsonObject) ?: continue
            if (seenQueries.add(operation.query)) {
                operations.add(operation)
            }
        }
        return operations
    }

    private fun parseJsonGraphQLBodiesWithOrgJson(body: String): List<GraphQLOperation> {
        return try {
            val array = JSONArray(body)
            val operations = mutableListOf<GraphQLOperation>()
            val seenQueries = linkedSetOf<String>()
            for (i in 0 until array.length()) {
                val obj = array.optJSONObject(i) ?: continue
                val query = extractQueryDocumentFromJsonObject(obj) ?: continue
                val operation = toGraphQLOperation(query) ?: continue
                if (seenQueries.add(operation.query)) {
                    operations.add(operation)
                }
            }
            operations
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseJsonGraphQLObject(jsonObject: JsonObject): GraphQLOperation? {
        val query = readJsonStringField(jsonObject, "query")
            ?: readJsonStringField(jsonObject, "mutation")
            ?: return null
        val variables = parseVariablesField(jsonObject.get("variables"))
        return toGraphQLOperation(query, variables)
    }

    private fun parseVariablesField(element: com.google.gson.JsonElement?): Map<String, Any?>? {
        if (element == null || element.isJsonNull || !element.isJsonObject) return null
        return gsonJsonElementToKotlin(element) as? Map<String, Any?>
    }

    private fun gsonJsonElementToKotlin(element: com.google.gson.JsonElement): Any? {
        return when {
            element.isJsonNull -> null
            element.isJsonPrimitive -> {
                val primitive = element.asJsonPrimitive
                when {
                    primitive.isBoolean -> primitive.asBoolean
                    primitive.isNumber -> primitive.asNumber
                    primitive.isString -> primitive.asString
                    else -> null
                }
            }
            element.isJsonObject -> {
                element.asJsonObject.entrySet().associate { (key, value) ->
                    key to gsonJsonElementToKotlin(value)
                }
            }
            element.isJsonArray -> element.asJsonArray.map { item -> gsonJsonElementToKotlin(item) }
            else -> null
        }
    }

    private fun readJsonStringField(jsonObject: JsonObject, field: String): String? {
        val element = jsonObject.get(field) ?: return null
        if (!element.isJsonPrimitive || !element.asJsonPrimitive.isString) return null
        return element.asString.trim().takeIf { it.isNotEmpty() }
    }

    private fun extractQueryDocumentFromJson(body: String): String? {
        return try {
            extractQueryDocumentFromJsonObject(JSONObject(body))
        } catch (_: Exception) {
            null
        }
    }

    private fun extractQueryDocumentFromJsonObject(jsonObject: JSONObject): String? {
        val query = when {
            jsonObject.has("query") && !jsonObject.isNull("query") -> jsonObject.optString("query", "")
            jsonObject.has("mutation") && !jsonObject.isNull("mutation") -> jsonObject.optString("mutation", "")
            else -> return null
        }
        return query.trim().takeIf { it.isNotEmpty() }
    }

    private fun looksLikeJsonGraphQLEnvelope(body: String): Boolean {
        return jsonGraphQLEnvelopePattern.containsMatchIn(body.trim())
    }

    private fun stripBom(value: String): String {
        return if (value.startsWith("\uFEFF")) value.substring(1) else value
    }

    private fun parseFormUrlEncodedBody(body: String): GraphQLOperation? {
        val params = parseQueryString(body)
        val queryDocument = params["query"] ?: return null
        val decoded = URLDecoder.decode(queryDocument, StandardCharsets.UTF_8).trim()
        return toGraphQLOperation(decoded)
    }

    private fun toGraphQLOperation(document: String, variables: Map<String, Any?>? = null): GraphQLOperation? {
        if (!looksLikeGraphQLDocument(document)) return null
        return GraphQLOperation(document, detectOperationType(document), variables)
    }

    private fun looksLikeGraphQLDocument(document: String): Boolean {
        if (document.isBlank()) return false
        val withoutLeadingComments = stripLeadingGraphQLComments(document)
        if (looksLikeNamedGraphQLOperation(withoutLeadingComments)) return true
        return shorthandSelectionSetPattern.containsMatchIn(withoutLeadingComments)
    }

    private fun stripLeadingGraphQLComments(document: String): String {
        var current = document.trimStart()
        while (current.startsWith("#")) {
            val newline = current.indexOf('\n')
            current = if (newline == -1) "" else current.substring(newline + 1).trimStart()
        }
        return current
    }

    private fun parseQueryString(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        return query.split('&').mapNotNull { part ->
            if (part.isBlank()) return@mapNotNull null
            val idx = part.indexOf('=')
            if (idx == -1) {
                part to ""
            } else {
                part.substring(0, idx) to part.substring(idx + 1)
            }
        }.toMap()
    }

    fun getGraphQLQuery(request: HttpRequest): String? {
        return getGraphQLOperation(request)?.query
    }

    fun isGraphQLRequest(request: HttpRequest): Boolean {
        return getGraphQLOperation(request) != null
    }

    private fun looksLikeNamedGraphQLOperation(body: String): Boolean {
        val trimmed = body.trimStart()
        return trimmed.startsWith("query", ignoreCase = true)
            || trimmed.startsWith("mutation", ignoreCase = true)
            || trimmed.startsWith("subscription", ignoreCase = true)
            || trimmed.startsWith("fragment", ignoreCase = true)
    }

    private fun detectOperationType(query: String): String {
        val trimmed = query.trimStart()
        return when {
            trimmed.startsWith("mutation", ignoreCase = true) -> "mutation"
            trimmed.startsWith("subscription", ignoreCase = true) -> "subscription"
            else -> "query"
        }
    }
    fun formatComment(strings: List<String>, maxLength: Int = 100): List<String> {
        val out = mutableListOf<String>()
        for (line in strings) {
            var currentLine = line
            while (currentLine.length > maxLength) {
                // Split the line into multiple lines
                val splitOn = currentLine.lastIndexOf(' ', maxLength)
                if (splitOn == -1) {
                    // Weird?
                    break
                }
                out.add("# ${currentLine.substring(0, splitOn)}")
                currentLine = currentLine.substring(splitOn + 1)
            }
            out.add("# $currentLine")
        }
        return out
    }

    fun unwrapType(type: GraphQLType): GraphQLType {
        var outputType: GraphQLType = type
        while (outputType is GraphQLModifiedType) {
            outputType = outputType.wrappedType
        }
        return outputType
    }

    fun isBuiltInScalarType(type: GraphQLScalarType): Boolean {
        val builtinScalars = arrayOf("Int", "Float", "String", "Boolean", "ID")

        return type.name in builtinScalars
    }
}
