package inql.attackvector

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import inql.bruteforcer.ThrottledClient
import inql.graphql.GraphQLRequestContext
import inql.graphql.GraphQLRequestPayload
import inql.graphql.GraphQLRequestTransformer
import inql.graphql.GraphQLTransportFormat
import inql.graphql.IntrospectionQuery
import inql.utils.withUpsertedHeader
import inql.utils.withoutContentHeaders
import org.json.JSONArray
import org.json.JSONObject

class ScanHttpClient(
    private val baseRequest: HttpRequest,
    val throttled: ThrottledClient,
) {
    private val gson = Gson()

    suspend fun sendQuery(query: String): JSONObject = throttled.send(query)

    suspend fun sendQueryExchange(query: String): Pair<JSONObject, TestEvidence?> {
        val req = buildQueryRequest(query)
        val exchange = sendRequest(req)
        val json = exchange.asJsonOrNull() ?: JSONObject()
        return Pair(json, exchange.toEvidence())
    }

    fun buildQueryRequest(query: String): HttpRequest {
        val body = gson.toJson(mapOf("query" to query))
        return baseRequest
            .withMethod("POST")
            .withUpsertedHeader("Content-Type", "application/json")
            .withBody(body)
    }

    suspend fun sendRequest(request: HttpRequest): HttpExchange {
        val response = throttled.sendRequest(request)
        return HttpExchange(request, response)
    }

    suspend fun sendJsonBody(body: String): HttpExchange {
        val req = baseRequest
            .withMethod("POST")
            .withUpsertedHeader("Content-Type", "application/json")
            .withBody(body)
        return sendRequest(req)
    }

    suspend fun sendBatchArray(count: Int, query: String = "query { __typename }"): HttpExchange {
        val array = JsonArray()
        repeat(count) {
            val entry = JsonObject()
            entry.addProperty("query", query)
            array.add(entry)
        }
        return sendJsonBody(gson.toJson(array))
    }

    suspend fun sendGetOperation(query: String): HttpExchange {
        val payload = GraphQLRequestPayload.single(query)
        val req = GraphQLRequestTransformer.applyPayload(
            baseRequest.withMethod("GET"),
            payload,
            GraphQLRequestContext(GraphQLTransportFormat.GET),
        )
        return sendRequest(req)
    }

    suspend fun sendFormUrlEncodedOperation(query: String): HttpExchange {
        val payload = GraphQLRequestPayload.single(query)
        val req = GraphQLRequestTransformer.applyPayload(
            baseRequest.withMethod("POST"),
            payload,
            GraphQLRequestContext(GraphQLTransportFormat.FORM_URLENCODED),
        )
        return sendRequest(req)
    }

    suspend fun sendFederationSdlExchange(): HttpExchange {
        return sendJsonBody("""{"query":"query{_service{sdl}}","operationName":null}""")
    }

    suspend fun sendIntrospectionExchange(): HttpExchange {
        var lastExchange: HttpExchange? = null
        for (version in IntrospectionQuery.Version.entries.asReversed()) {
            val body = gson.toJson(mapOf("query" to IntrospectionQuery.get(version)))
            val exchange = sendJsonBody(body)
            lastExchange = exchange
            val json = exchange.asJsonOrNull()
            if (json?.optJSONObject("data")?.optJSONObject("__schema") != null) {
                return exchange
            }
            if (exchange.statusCode in 200..299 && json != null && !json.has("errors")) {
                return exchange
            }
        }
        return lastExchange ?: sendJsonBody("{}")
    }

    suspend fun probePath(path: String): HttpExchange {
        return sendRequest(baseRequest.withPath(path))
    }

    suspend fun probePathGet(path: String): HttpExchange {
        val req = baseRequest
            .withMethod("GET")
            .withPath(path)
            .withBody("")
            .withoutContentHeaders()
        return sendRequest(req)
    }

    data class HttpExchange(
        val request: HttpRequest,
        val response: HttpResponse?,
    ) {
        val statusCode: Int get() = response?.statusCode()?.toInt() ?: 0
        val body: String get() = response?.bodyToString() ?: ""

        fun toEvidence(): TestEvidence? {
            val resp = response ?: return null
            return TestEvidence(request, resp)
        }

        fun asJsonOrNull(): JSONObject? = try {
            if (body.isBlank()) null else JSONObject(body)
        } catch (_: Exception) {
            null
        }

        fun asJsonArrayOrNull(): JSONArray? = try {
            if (body.isBlank()) null else JSONArray(body)
        } catch (_: Exception) {
            null
        }
    }
}
