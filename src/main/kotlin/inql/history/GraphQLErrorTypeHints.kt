package inql.history

import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.schema.corrections.GraphQLErrorPathParser
import inql.schema.corrections.SchemaArgumentPathResolver
import org.json.JSONArray
import org.json.JSONObject

/**
 * Extracts concrete GraphQL type names from validation errors in response bodies.
 */
internal object GraphQLErrorTypeHints {
    data class ArgumentTypeHint(
        val parentType: String,
        val fieldName: String,
        val argumentName: String,
        val expectedType: String,
    )

    data class Hints(
        val argumentHints: List<ArgumentTypeHint> = emptyList(),
        val typeRenames: List<Pair<String, String>> = emptyList(),
    )

    private val gson = Gson()

    private val argumentMismatchMessage = Regex(
        """(?:Type|Nullability) mismatch on variable \$(?<variable>\w+) and argument (?<argument>\w+) \((?<variableType>[^/]+) / (?<argumentType>[^)]+)\)""",
        RegexOption.IGNORE_CASE,
    )

    fun parse(responseBody: String?): Hints {
        if (responseBody.isNullOrBlank()) return Hints()
        val errors = parseErrors(responseBody) ?: return Hints()
        val argumentHints = mutableListOf<ArgumentTypeHint>()
        val renames = mutableListOf<Pair<String, String>>()

        for (i in 0 until errors.length()) {
            val error = errors.optJSONObject(i) ?: continue
            argumentHints.addAll(parseArgumentHint(error))
            renames.addAll(parseTypeRename(error))
        }

        return Hints(
            argumentHints = argumentHints.distinct(),
            typeRenames = renames.distinct(),
        )
    }

    private fun parseArgumentHint(error: JSONObject): List<ArgumentTypeHint> {
        val message = error.optString("message", "")
        val extensions = error.optJSONObject("extensions")
        val path = error.optJSONArray("path") ?: extensions?.optJSONArray("path")

        val argumentType = extractArgumentTypeFromMessage(message)
            ?: extensions?.optString("argumentType")?.takeIf { it.isNotBlank() }

        val fieldLocation = SchemaArgumentPathResolver.parseArgumentLocation(path)
        if (fieldLocation == null || argumentType.isNullOrBlank()) {
            return emptyList()
        }

        val (fieldName, argumentName) = fieldLocation
        val parentType = SchemaArgumentPathResolver.inferredParentTypeFromErrorPath(path, fieldName)
            ?: return emptyList()
        val expectedType = GraphQLErrorPathParser.normalizeTypeName(argumentType) ?: return emptyList()
        return listOf(
            ArgumentTypeHint(
                parentType = parentType,
                fieldName = fieldName,
                argumentName = argumentName,
                expectedType = expectedType,
            ),
        )
    }

    private fun parseTypeRename(error: JSONObject): List<Pair<String, String>> {
        val message = error.optString("message", "")
        val extensions = error.optJSONObject("extensions")
        val match = argumentMismatchMessage.find(message) ?: return emptyList()

        val variableType = GraphQLErrorPathParser.normalizeTypeName(
            match.groups["variableType"]?.value ?: extensions?.optString("typeName"),
        ) ?: return emptyList()
        val argumentType = GraphQLErrorPathParser.normalizeTypeName(
            match.groups["argumentType"]?.value ?: extensions?.optString("argumentType"),
        ) ?: return emptyList()

        if (variableType == argumentType) return emptyList()
        return listOf(variableType to argumentType)
    }

    private fun extractArgumentTypeFromMessage(message: String): String? {
        val match = argumentMismatchMessage.find(message) ?: return null
        return match.groups["argumentType"]?.value?.trim()
    }

    private fun parseErrors(responseBody: String): JSONArray? {
        val trimmed = responseBody.trim()
        if (trimmed.startsWith("[")) {
            return parseBatchErrors(trimmed)
        }
        return try {
            val json = gson.fromJson(trimmed, JsonObject::class.java)
            when {
                json.has("errors") && json.get("errors").isJsonArray ->
                    JSONArray(json.getAsJsonArray("errors").toString())
                else -> null
            }
        } catch (_: Exception) {
            try {
                JSONObject(trimmed).optJSONArray("errors")
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun parseBatchErrors(responseBody: String): JSONArray? {
        return try {
            val array = JSONArray(responseBody)
            val merged = JSONArray()
            for (index in 0 until array.length()) {
                val entry = array.optJSONObject(index) ?: continue
                val errors = entry.optJSONArray("errors") ?: continue
                for (errorIndex in 0 until errors.length()) {
                    merged.put(errors.opt(errorIndex))
                }
            }
            if (merged.length() == 0) null else merged
        } catch (_: Exception) {
            null
        }
    }
}
