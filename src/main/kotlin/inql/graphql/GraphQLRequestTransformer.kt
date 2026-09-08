package inql.graphql

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import inql.utils.get
import inql.utils.withUpsertedHeader
import inql.utils.withoutContentHeaders
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

data class GraphQLRequestPayload(
    val operations: List<Operation>,
) {
    data class Operation(
        val query: String,
        val variables: String? = null,
        val operationName: String? = null,
    )

    val isBatch: Boolean get() = operations.size > 1

    val query: String get() = operations.first().query
    val variables: String? get() = operations.first().variables
    val operationName: String? get() = operations.first().operationName

    fun withFirstOperation(
        query: String,
        variables: String?,
        operationName: String?,
    ): GraphQLRequestPayload {
        if (operations.isEmpty()) {
            return single(query, variables, operationName)
        }
        val updated = operations.toMutableList()
        updated[0] = Operation(query, variables, operationName)
        return copy(operations = updated)
    }

    companion object {
        fun single(
            query: String,
            variables: String? = null,
            operationName: String? = null,
        ): GraphQLRequestPayload {
            return GraphQLRequestPayload(listOf(Operation(query, variables, operationName)))
        }
    }
}

enum class GraphQLTransportFormat(val menuLabel: String?) {
    GET("GET query"),
    JSON("POST application/json"),
    FORM_URLENCODED("POST application/x-www-form-urlencoded"),
    MULTIPART("POST multipart/form-data"),
    RAW_GRAPHQL(null),
    ;

    fun showInTransformMenu(): Boolean = menuLabel != null
}

data class GraphQLRequestContext(
    val format: GraphQLTransportFormat,
    val multipartBoundary: String? = null,
)

class GraphQLRequestTransformException(message: String) : Exception(message)

object GraphQLRequestTransformer {
    private val gson = Gson()
    private const val MULTIPART_BOUNDARY = "----WebKitFormBoundaryInQL7MA4YWxkTrZu0gW"
    private val GRAPHQL_QUERY_PARAMS = setOf("query", "variables", "operationName")

    fun transform(request: HttpRequest, target: GraphQLTransportFormat): HttpRequest {
        val payload = parsePayload(request)
            ?: throw GraphQLRequestTransformException(
                "Could not parse a GraphQL request. Ensure the request contains a valid query " +
                    "(JSON body, GET parameters, form data, or multipart form data).",
            )

        if (payload.isBatch && target != GraphQLTransportFormat.JSON) {
            throw GraphQLRequestTransformException(
                "Batched GraphQL requests (JSON array body) can only be transformed to POST application/json.",
            )
        }

        return applyPayload(request, payload, GraphQLRequestContext(target))
    }

    fun detectRequestContext(request: HttpRequest): GraphQLRequestContext {
        return try {
            when (request.method().uppercase()) {
                "GET" -> GraphQLRequestContext(GraphQLTransportFormat.GET)
                "POST" -> detectPostRequestContext(request)
                else -> GraphQLRequestContext(GraphQLTransportFormat.JSON)
            }
        } catch (_: Exception) {
            GraphQLRequestContext(GraphQLTransportFormat.JSON)
        }
    }

    fun payloadsEqual(a: HttpRequest, b: HttpRequest): Boolean {
        val payloadA = parsePayload(a) ?: return false
        val payloadB = parsePayload(b) ?: return false
        return payloadA == payloadB
    }

    private fun detectPostRequestContext(request: HttpRequest): GraphQLRequestContext {
        val contentTypeHeader = request.headers().get("content-type") ?: ""
        val contentType = contentTypeHeader.lowercase().substringBefore(';').trim()
        val body = request.bodyToString()

        when (contentType) {
            "application/x-www-form-urlencoded" -> return GraphQLRequestContext(GraphQLTransportFormat.FORM_URLENCODED)
            "multipart/form-data" -> {
                val boundary = extractMultipartBoundary(contentTypeHeader) ?: extractMultipartBoundaryFromBody(body)
                return GraphQLRequestContext(GraphQLTransportFormat.MULTIPART, boundary ?: MULTIPART_BOUNDARY)
            }
            "application/graphql" -> return GraphQLRequestContext(GraphQLTransportFormat.RAW_GRAPHQL)
            "application/json" -> return GraphQLRequestContext(GraphQLTransportFormat.JSON)
        }

        if (body.isNotBlank()) {
            detectMultipartContext(body, contentTypeHeader)?.let { return it }
            if (parseFromJson(body) != null) {
                return GraphQLRequestContext(GraphQLTransportFormat.JSON)
            }
            if (looksLikeFormUrlEncoded(body) && parseFromQueryString(body) != null) {
                return GraphQLRequestContext(GraphQLTransportFormat.FORM_URLENCODED)
            }
        }

        return GraphQLRequestContext(GraphQLTransportFormat.JSON)
    }

    private fun detectMultipartContext(body: String, contentTypeHeader: String): GraphQLRequestContext? {
        val boundary = extractMultipartBoundary(contentTypeHeader) ?: extractMultipartBoundaryFromBody(body) ?: return null
        if (!parseMultipartFields(body, boundary).containsKey("query")) return null
        return GraphQLRequestContext(GraphQLTransportFormat.MULTIPART, boundary)
    }

    private fun extractMultipartBoundaryFromBody(body: String): String? {
        if (!body.startsWith("--")) return null
        val firstLine = body.substringBefore("\r\n").substringBefore('\n').trim()
        if (!firstLine.startsWith("--")) return null
        return firstLine.removePrefix("--").takeIf { it.isNotEmpty() }
    }

    private fun looksLikeFormUrlEncoded(body: String): Boolean {
        val trimmed = body.trimStart()
        return trimmed.contains('=') && !trimmed.startsWith("{") && !trimmed.startsWith("[") && !trimmed.startsWith("--")
    }

    fun applyPayload(
        request: HttpRequest,
        payload: GraphQLRequestPayload,
        context: GraphQLRequestContext,
    ): HttpRequest {
        if (payload.isBatch && context.format != GraphQLTransportFormat.JSON) {
            throw GraphQLRequestTransformException(
                "Batched GraphQL requests (JSON array body) can only be sent as POST application/json.",
            )
        }

        return when (context.format) {
            GraphQLTransportFormat.JSON -> toJsonRequest(request, payload)
            GraphQLTransportFormat.GET -> toGetRequest(request, payload)
            GraphQLTransportFormat.FORM_URLENCODED -> toFormUrlEncodedRequest(request, payload)
            GraphQLTransportFormat.MULTIPART -> toMultipartRequest(
                request,
                payload,
                context.multipartBoundary ?: MULTIPART_BOUNDARY,
            )
            GraphQLTransportFormat.RAW_GRAPHQL -> toRawGraphqlRequest(request, payload)
        }
    }

    fun parsePayload(request: HttpRequest): GraphQLRequestPayload? {
        return try {
            when (request.method().uppercase()) {
                "GET" -> {
                    val uri = URI.create(request.url())
                    parseFromQueryString(uri.rawQuery ?: "")
                }
                "POST" -> parseFromPostBody(request)
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun parseFromPostBody(request: HttpRequest): GraphQLRequestPayload? {
        val body = request.bodyToString()
        if (body.isBlank()) return null

        val contentType = request.headers().get("content-type")
            ?.lowercase()
            ?.substringBefore(';')
            ?.trim()

        return when (contentType) {
            "application/graphql" -> GraphQLRequestPayload.single(query = stripBom(body.trim()))
            "application/x-www-form-urlencoded" -> parseFromQueryString(body)
            "multipart/form-data" -> parseFromMultipart(body, request.headers().get("content-type") ?: return null)
            "application/json" -> parseFromJson(body)
            else -> {
                parseFromJson(body)
                    ?: parseFromQueryString(body)
                    ?: parseFromMultipart(body, request.headers().get("content-type") ?: "")
                    ?: parseRawDocument(body)
            }
        }
    }

    private fun parseFromJson(body: String): GraphQLRequestPayload? {
        val trimmed = stripBom(body.trim())
        return when {
            trimmed.startsWith("[") -> parseFromJsonArray(trimmed)
            trimmed.startsWith("{") -> parseFromJsonObject(trimmed)
            else -> null
        }
    }

    private fun parseFromJsonArray(body: String): GraphQLRequestPayload? {
        return try {
            val array = gson.fromJson(body, JsonArray::class.java) ?: return null
            val operations = array.mapNotNull { element ->
                if (!element.isJsonObject) return@mapNotNull null
                parseOperationFromJsonObject(element.asJsonObject)
            }
            if (operations.isEmpty()) return null
            GraphQLRequestPayload(operations)
        } catch (_: Exception) {
            null
        }
    }

    private fun parseFromJsonObject(body: String): GraphQLRequestPayload? {
        return try {
            val json = gson.fromJson(body, JsonObject::class.java) ?: return null
            parseOperationFromJsonObject(json)?.let { GraphQLRequestPayload(listOf(it)) }
        } catch (_: Exception) {
            null
        }
    }

    private fun parseOperationFromJsonObject(json: JsonObject): GraphQLRequestPayload.Operation? {
        val query = readJsonStringField(json, "query")
            ?: readJsonStringField(json, "mutation")
            ?: return null
        if (!Utils.isGraphQLDocument(query)) return null

        val variables = json.get("variables")?.takeUnless { it.isJsonNull }?.toString()
        val operationName = readJsonStringField(json, "operationName")

        return GraphQLRequestPayload.Operation(query, variables, operationName)
    }

    private fun readJsonStringField(json: JsonObject, field: String): String? {
        val element = json.get(field) ?: return null
        if (!element.isJsonPrimitive || !element.asJsonPrimitive.isString) return null
        return element.asString.trim().takeIf { it.isNotEmpty() }
    }

    private fun parseFromQueryString(queryString: String): GraphQLRequestPayload? {
        if (queryString.isBlank()) return null
        val params = parseQueryString(queryString)
        val queryDocument = params["query"] ?: return null
        val query = URLDecoder.decode(queryDocument, StandardCharsets.UTF_8).trim()
        if (!Utils.isGraphQLDocument(query)) return null

        val variables = params["variables"]?.let { URLDecoder.decode(it, StandardCharsets.UTF_8) }
        val operationName = params["operationName"]?.let { URLDecoder.decode(it, StandardCharsets.UTF_8) }

        return GraphQLRequestPayload.single(query = query, variables = variables, operationName = operationName)
    }

    private fun parseFromMultipart(body: String, contentType: String): GraphQLRequestPayload? {
        val boundary = extractMultipartBoundary(contentType) ?: extractMultipartBoundaryFromBody(body) ?: return null
        val fields = parseMultipartFields(body, boundary)
        if (fields.isEmpty()) return null

        val query = fields["query"]?.trim() ?: return null
        if (!Utils.isGraphQLDocument(query)) return null

        return GraphQLRequestPayload.single(
            query = query,
            variables = fields["variables"]?.trim()?.takeIf { it.isNotEmpty() },
            operationName = fields["operationName"]?.trim()?.takeIf { it.isNotEmpty() },
        )
    }

    private fun parseRawDocument(body: String): GraphQLRequestPayload? {
        val document = stripBom(body.trim())
        if (!Utils.isGraphQLDocument(document)) return null
        return GraphQLRequestPayload.single(query = document)
    }

    private fun toGetRequest(request: HttpRequest, payload: GraphQLRequestPayload): HttpRequest {
        val uri = URI.create(request.url())
        val basePath = uri.rawPath ?: "/"
        val remaining = parseQueryString(uri.rawQuery ?: "")
            .filterKeys { it !in GRAPHQL_QUERY_PARAMS }
        val path = pathWithQueryString(basePath, remaining, buildGraphQLQueryString(payload))

        return request
            .withoutContentHeaders()
            .withMethod("GET")
            .withPath(path)
            .withBody("")
    }

    private fun toFormUrlEncodedRequest(request: HttpRequest, payload: GraphQLRequestPayload): HttpRequest {
        return toPostRequest(
            request,
            "application/x-www-form-urlencoded",
            buildGraphQLQueryString(payload),
        )
    }

    private fun toMultipartRequest(
        request: HttpRequest,
        payload: GraphQLRequestPayload,
        boundary: String,
    ): HttpRequest {
        return toPostRequest(
            request,
            "multipart/form-data; boundary=$boundary",
            buildMultipartBody(payload, boundary),
        )
    }

    private fun toRawGraphqlRequest(request: HttpRequest, payload: GraphQLRequestPayload): HttpRequest {
        return toPostRequest(request, "application/graphql", payload.query)
    }

    fun applyRawJsonBody(request: HttpRequest, body: String): HttpRequest {
        return toPostRequest(request, "application/json", body)
    }

    private fun toJsonRequest(request: HttpRequest, payload: GraphQLRequestPayload): HttpRequest {
        return toPostRequest(request, "application/json", buildJsonBody(payload))
    }

    private fun toPostRequest(request: HttpRequest, contentType: String, body: String): HttpRequest {
        return request
            .withoutContentHeaders()
            .withMethod("POST")
            .withPath(pathWithoutGraphQLQueryParams(request.url()))
            .withUpsertedHeader("Content-Type", contentType)
            .withBody(body)
    }

    private fun pathWithoutGraphQLQueryParams(url: String): String {
        val uri = URI.create(url)
        val basePath = uri.rawPath ?: "/"
        val remaining = parseQueryString(uri.rawQuery ?: "")
            .filterKeys { it !in GRAPHQL_QUERY_PARAMS }
        return pathWithQueryString(basePath, remaining)
    }

    private fun pathWithQueryString(
        basePath: String,
        encodedParams: Map<String, String>,
        additionalQueryString: String = "",
    ): String {
        val parts = mutableListOf<String>()
        parts.addAll(encodedParams.entries.map { "${it.key}=${it.value}" })
        if (additionalQueryString.isNotEmpty()) {
            parts.add(additionalQueryString)
        }
        if (parts.isEmpty()) return basePath
        return "$basePath?${parts.joinToString("&")}"
    }

    private fun buildJsonBody(payload: GraphQLRequestPayload): String {
        if (payload.operations.size == 1) {
            return gson.toJson(operationToJsonObject(payload.operations.first()))
        }
        val array = JsonArray()
        for (operation in payload.operations) {
            array.add(operationToJsonObject(operation))
        }
        return gson.toJson(array)
    }

    private fun operationToJsonObject(operation: GraphQLRequestPayload.Operation): JsonObject {
        val body = JsonObject()
        body.addProperty("query", operation.query)
        operation.operationName?.let { body.addProperty("operationName", it) }
        if (operation.variables != null) {
            body.add("variables", gson.fromJson(operation.variables, JsonElement::class.java))
        }
        return body
    }

    private fun buildGraphQLQueryString(payload: GraphQLRequestPayload): String {
        val operation = payload.operations.first()
        val parts = mutableListOf<String>()
        parts += encodeQueryParam("query", operation.query)
        operation.variables?.let { parts += encodeQueryParam("variables", it) }
        operation.operationName?.let { parts += encodeQueryParam("operationName", it) }
        return parts.joinToString("&")
    }

    private fun encodeQueryParam(name: String, value: String): String {
        return "${URLEncoder.encode(name, StandardCharsets.UTF_8)}=" +
            URLEncoder.encode(value, StandardCharsets.UTF_8)
    }

    private fun buildMultipartBody(payload: GraphQLRequestPayload, boundary: String): String {
        val operation = payload.operations.first()
        val fields = linkedMapOf("query" to operation.query)
        operation.variables?.let { fields["variables"] = it }
        operation.operationName?.let { fields["operationName"] = it }

        return buildString {
            for ((name, value) in fields) {
                append("--").append(boundary).append("\r\n")
                append("Content-Disposition: form-data; name=\"").append(name).append("\"\r\n")
                append("\r\n")
                append(value)
                append("\r\n")
            }
            append("--").append(boundary).append("--\r\n")
        }
    }

    private fun parseMultipartFields(body: String, boundary: String): Map<String, String> {
        val delimiter = "--$boundary"
        val fields = linkedMapOf<String, String>()
        for (part in body.split(delimiter)) {
            val trimmed = part.trim('\r', '\n', ' ')
            if (trimmed.isEmpty() || trimmed == "--") continue

            val headerEnd = trimmed.indexOf("\r\n\r\n")
            if (headerEnd == -1) continue

            val headers = trimmed.substring(0, headerEnd)
            var content = trimmed.substring(headerEnd + 4)
            if (content.endsWith("\r\n")) {
                content = content.dropLast(2)
            }

            val nameMatch = Regex("""name="([^"]+)"""").find(headers) ?: continue
            fields[nameMatch.groupValues[1]] = content
        }
        return fields
    }

    private fun extractMultipartBoundary(contentType: String): String? {
        val match = Regex("""boundary=([^;\s]+)""", RegexOption.IGNORE_CASE).find(contentType) ?: return null
        return match.groupValues[1].trim().removeSurrounding("\"")
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

    private fun stripBom(value: String): String {
        return if (value.startsWith("\uFEFF")) value.substring(1) else value
    }
}
