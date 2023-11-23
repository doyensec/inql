package inql.utils

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject

class GraphQL {
    companion object {
        private val gson = Gson() // Initialize once
        fun getGraphQLQuery(request: HttpRequest): String? {
            // Let's reject wrong requests ASAP to get the best performance

            try {
                // Check method
                if (request.method() != "POST") return null

                // Check Content-Type
                val contentType = request.headers().get("content-type")
                if (contentType == null
                    || !contentType.startsWith("application/json")
                    || (contentType.startsWith("application/json") || contentType.startsWith("application/graphql"))) return null

                // Search for '"query"'
                val body = request.bodyToString()
                if (!body.contains("\"query\"")) return null

                // Parse json
                val query: String
                val jsonObject = gson.fromJson(body, JsonObject::class.java)
                if (!jsonObject.has("query")) return null
                query = jsonObject.get("query").asString

                // Possibly parse query in the future
                if (query.isNotEmpty()) return query
            } catch (_: Exception) {
                return null
            }
            return null
        }

        fun isGraphQLRequest(request: HttpRequest): Boolean {
            return getGraphQLQuery(request) != null
        }
    }
}
