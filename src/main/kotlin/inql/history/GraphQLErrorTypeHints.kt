package inql.history

import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONArray
import org.json.JSONObject

/**
 * Extracts concrete GraphQL type names from validation errors in response bodies.
 */
internal object GraphQLErrorTypeHints {
    data class ArgumentTypeHint(
        val rootType: String,
        val fieldName: String,
        val argumentName: String,
        val expectedType: String,
    )

    data class Hints(
        val argumentHints: List<ArgumentTypeHint> = emptyList(),
    )

    private val gson = Gson()

    private val argumentMismatchMessage = Regex(
        """(?:Type|Nullability) mismatch on variable \$(?<variable>\w+) and argument (?<argument>\w+) \((?<variableType>[^/]+) / (?<argumentType>[^)]+)\)""",
        RegexOption.IGNORE_CASE,
    )

    fun parse(responseBody: String?): Hints {
        if (responseBody.isNullOrBlank()) return Hints()
        val errors = parseErrors(responseBody) ?: return Hints()
        val hints = mutableListOf<ArgumentTypeHint>()

        for (i in 0 until errors.length()) {
            val error = errors.optJSONObject(i) ?: continue
            hints.addAll(parseErrorObject(error))
        }

        return Hints(argumentHints = hints.distinct())
    }

    private fun parseErrorObject(error: JSONObject): List<ArgumentTypeHint> {
        val message = error.optString("message", "")
        val extensions = error.optJSONObject("extensions")
        val pathHint = parsePathHint(error.optJSONArray("path"), extensions?.optJSONArray("path"))

        val argumentType = extractArgumentTypeFromMessage(message)
            ?: extensions?.optString("argumentType")?.takeIf { it.isNotBlank() }

        if (pathHint == null || argumentType.isNullOrBlank()) {
            return emptyList()
        }

        return listOf(
            ArgumentTypeHint(
                rootType = pathHint.rootType,
                fieldName = pathHint.fieldName,
                argumentName = pathHint.argumentName,
                expectedType = normalizeSdlType(argumentType),
            ),
        )
    }

    private data class PathHint(
        val rootType: String,
        val fieldName: String,
        val argumentName: String,
    )

    private fun parsePathHint(primary: JSONArray?, fallback: JSONArray?): PathHint? {
        val path = primary ?: fallback ?: return null
        val segments = (0 until path.length()).mapNotNull { index ->
            when (val value = path.opt(index)) {
                is String -> value
                else -> value?.toString()
            }
        }
        if (segments.size < 3) return null

        val rootType = when (segments[0].lowercase()) {
            "mutation" -> "Mutation"
            "subscription" -> "Subscription"
            "query" -> "Query"
            else -> return null
        }

        return PathHint(
            rootType = rootType,
            fieldName = segments[1],
            argumentName = segments[2],
        )
    }

    private fun extractArgumentTypeFromMessage(message: String): String? {
        val match = argumentMismatchMessage.find(message) ?: return null
        return match.groups["argumentType"]?.value?.trim()
    }

    private fun normalizeSdlType(type: String): String {
        return type.trim()
    }

    private fun parseErrors(responseBody: String): JSONArray? {
        return try {
            val json = gson.fromJson(responseBody, JsonObject::class.java)
            when {
                json.has("errors") && json.get("errors").isJsonArray ->
                    JSONArray(json.getAsJsonArray("errors").toString())
                else -> null
            }
        } catch (_: Exception) {
            try {
                JSONObject(responseBody).optJSONArray("errors")
            } catch (_: Exception) {
                null
            }
        }
    }
}
