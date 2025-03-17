package inql.graphql

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import graphql.schema.GraphQLModifiedType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLType
import inql.utils.get

object Utils {
    private val gson = Gson() // Initialize once
    fun getGraphQLQuery(request: HttpRequest): String? {
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
            val query: String
            val jsonObject = gson.fromJson(body, JsonObject::class.java)
            if (!jsonObject.has("query")) {
                return null
            }
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
fun formatComment(string: String, maxLength: Int = 100): String {
    val sb = StringBuilder()
    for (line in string.lines()) {
        var currentLine = line
        while (currentLine.length > maxLength) {
            // Split the line into multiple lines
            val splitOn = currentLine.lastIndexOf(' ', maxLength)
            if (splitOn == -1) {
                // Weird?
                break
            }
            sb.appendLine("# ${currentLine.substring(0, splitOn)}")
            currentLine = currentLine.substring(splitOn + 1)
        }
        sb.appendLine("# $currentLine")
    }
    return sb.toString()
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
