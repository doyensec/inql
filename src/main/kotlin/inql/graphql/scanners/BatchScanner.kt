package inql.graphql.scanners

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import inql.Logger

class BatchScanner(private val requestTemplate: HttpRequest) {

    enum class BatchType { ALIAS, ARRAY }

    data class BatchScanResult(
        val type: BatchType,
        val supported: Boolean,
        val statusCode: Int,
        val response: HttpResponse?,
        val detail: String,
    )

    companion object {
        // Minimal introspection query — guaranteed to work on any GraphQL server
        private const val PROBE_QUERY = "__typename"

        /**
         * Build the alias-batched query body.
         *
         * Produces:
         * {
         *   "query": "query { alias1: __typename alias2: __typename }"
         * }
         *
         * If the server resolves both aliases, batching via aliases is supported.
         */
        fun buildAliasBatchBody(): String {
            val obj = JsonObject()
            obj.addProperty(
                "query",
                "query { inql_batch_alias1: $PROBE_QUERY inql_batch_alias2: $PROBE_QUERY }"
            )
            return Gson().toJson(obj)
        }

        /**
         * Build the array-batched query body.
         *
         * Produces:
         * [
         *   { "query": "query { __typename }" },
         *   { "query": "query { __typename }" }
         * ]
         *
         * If the server returns an array of two results, array batching is supported.
         */
        fun buildArrayBatchBody(): String {
            val arr = JsonArray()
            for (i in 1..2) {
                val obj = JsonObject()
                obj.addProperty("query", "query { $PROBE_QUERY }")
                arr.add(obj)
            }
            return Gson().toJson(arr)
        }

        /**
         * Analyze whether the alias batch response succeeded.
         *
         * Success criteria:
         *   - HTTP 200
         *   - Body is valid JSON
         *   - `data` object contains both `inql_batch_alias1` and `inql_batch_alias2`
         *   - No `errors` array, OR errors array is empty
         */
        fun analyzeAliasBatchResponse(resp: HttpResponse): Pair<Boolean, String> {
            if (resp.statusCode() !in 200..299) {
                return false to "Non-2xx status code: ${resp.statusCode()}"
            }

            return try {
                val body = resp.bodyToString()
                val json = JsonParser.parseString(body)

                if (!json.isJsonObject) {
                    return false to "Response body is not a JSON object"
                }

                val root = json.asJsonObject
                val data = root.getAsJsonObject("data")
                    ?: return false to "No 'data' field in response"

                val hasAlias1 = data.has("inql_batch_alias1")
                val hasAlias2 = data.has("inql_batch_alias2")

                if (hasAlias1 && hasAlias2) {
                    // Check for errors
                    val errors = root.getAsJsonArray("errors")
                    if (errors != null && errors.size() > 0) {
                        false to "Both aliases resolved but errors present: ${errors.size()} error(s)"
                    } else {
                        true to "Both aliases resolved successfully"
                    }
                } else {
                    false to "Missing aliases in response (alias1=$hasAlias1, alias2=$hasAlias2)"
                }
            } catch (e: Exception) {
                false to "Failed to parse response: ${e.message}"
            }
        }

        /**
         * Analyze whether the array batch response succeeded.
         *
         * Success criteria:
         *   - HTTP 200
         *   - Body is a JSON array with exactly 2 elements
         *   - Each element has a `data` object
         */
        fun analyzeArrayBatchResponse(resp: HttpResponse): Pair<Boolean, String> {
            if (resp.statusCode() !in 200..299) {
                return false to "Non-2xx status code: ${resp.statusCode()}"
            }

            return try {
                val body = resp.bodyToString()
                val json = JsonParser.parseString(body)

                if (!json.isJsonArray) {
                    // Some servers return a single error object when array batching
                    // is disabled — that's a clear "not supported"
                    if (json.isJsonObject) {
                        val errors = json.asJsonObject.getAsJsonArray("errors")
                        if (errors != null && errors.size() > 0) {
                            return false to "Server returned error object instead of array"
                        }
                    }
                    return false to "Response body is not a JSON array"
                }

                val arr = json.asJsonArray
                if (arr.size() != 2) {
                    return false to "Expected 2 results, got ${arr.size()}"
                }

                val allHaveData = arr.all {
                    it.isJsonObject && it.asJsonObject.has("data")
                }

                if (allHaveData) {
                    true to "Server returned ${arr.size()} results in array"
                } else {
                    false to "Array elements missing 'data' field"
                }
            } catch (e: Exception) {
                false to "Failed to parse response: ${e.message}"
            }
        }
    }

    /**
     * Run both batch probes against the target and return results.
     */
    fun scan(): List<BatchScanResult> {
        val results = mutableListOf<BatchScanResult>()

        // --- Alias Batching ---
        try {
            val aliasBody = buildAliasBatchBody()
            val aliasReq = requestTemplate
                .withHeader("Content-Type", "application/json")
                .withBody(aliasBody)

            Logger.debug("BatchScanner: sending alias batch probe to ${aliasReq.url()}")
            val aliasResp = Burp.Montoya.http().sendRequest(aliasReq)
            val resp = aliasResp.response()

            val (supported, detail) = analyzeAliasBatchResponse(resp)
            results.add(
                BatchScanResult(
                    type = BatchType.ALIAS,
                    supported = supported,
                    statusCode = resp.statusCode().toInt(),
                    response = resp,
                    detail = detail,
                )
            )
            Logger.info("BatchScanner: alias batching ${if (supported) "SUPPORTED" else "not supported"} — $detail")
        } catch (e: Exception) {
            Logger.error("BatchScanner: alias probe failed: ${e.message}")
            results.add(
                BatchScanResult(
                    type = BatchType.ALIAS,
                    supported = false,
                    statusCode = 0,
                    response = null,
                    detail = "Request failed: ${e.message}",
                )
            )
        }

        // --- Array Batching ---
        try {
            val arrayBody = buildArrayBatchBody()
            val arrayReq = requestTemplate
                .withHeader("Content-Type", "application/json")
                .withBody(arrayBody)

            Logger.debug("BatchScanner: sending array batch probe to ${arrayReq.url()}")
            val arrayResp = Burp.Montoya.http().sendRequest(arrayReq)
            val resp = arrayResp.response()

            val (supported, detail) = analyzeArrayBatchResponse(resp)
            results.add(
                BatchScanResult(
                    type = BatchType.ARRAY,
                    supported = supported,
                    statusCode = resp.statusCode().toInt(),
                    response = resp,
                    detail = detail,
                )
            )
            Logger.info("BatchScanner: array batching ${if (supported) "SUPPORTED" else "not supported"} — $detail")
        } catch (e: Exception) {
            Logger.error("BatchScanner: array probe failed: ${e.message}")
            results.add(
                BatchScanResult(
                    type = BatchType.ARRAY,
                    supported = false,
                    statusCode = 0,
                    response = null,
                    detail = "Request failed: ${e.message}",
                )
            )
        }

        return results
    }

    /**
     * Return a human-readable summary of batch scan results.
     */
    fun scanAsString(): String {
        val results = scan()
        return results.joinToString("\n") { r ->
            val status = if (r.supported) "✓ SUPPORTED" else "✗ Not supported"
            val typeLabel = when (r.type) {
                BatchType.ALIAS -> "Alias Batching"
                BatchType.ARRAY -> "Array Batching"
            }
            "$typeLabel: $status (HTTP ${r.statusCode}) — ${r.detail}"
        }
    }
}
