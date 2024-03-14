package inql.graphql

import burp.api.montoya.http.message.requests.HttpRequest
import inql.utils.get
import kotlinx.serialization.json.*

class Utils {
    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        fun isGraphQLRequest(request: HttpRequest): Boolean {
            return getGraphQLQuery(request) != null
        }

        private fun getGraphQLQuery(request: HttpRequest): String? {
            // Let's reject wrong requests ASAP to get the best performance
            try {
                // Check method
                if (request.method() != "POST") {
                    return null
                }

                // Check Content-Type
                val contentType = request.headers().get("content-type")
                if (contentType == null
                    || !(contentType.startsWith("application/json") || contentType.startsWith("application/graphql"))) {
                    return null
                }

                // Search for '"query"'
                val body = request.bodyToString()
                if (!body.contains("\"query\"")) {
                    return null
                }

                // Parse json
                val parsed = json.parseToJsonElement(body).jsonObject
                return if (parsed.containsKey("query")) {
                    parsed["query"]?.jsonPrimitive?.contentOrNull
                } else {
                    null
                }
            } catch (_: Exception) {
                return null
            }
        }
    }
}
