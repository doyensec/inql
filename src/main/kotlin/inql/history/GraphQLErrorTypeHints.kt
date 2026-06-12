package inql.history

import inql.schema.corrections.GraphQLErrorPathParser
import inql.schema.corrections.GraphQLErrorResponseParser
import inql.schema.corrections.SchemaArgumentPathResolver
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

    private val argumentMismatchMessage = Regex(
        """(?:Type|Nullability) mismatch on variable \$(?<variable>\w+) and argument (?<argument>\w+) \((?<variableType>[^/]+) / (?<argumentType>[^)]+)\)""",
        RegexOption.IGNORE_CASE,
    )

    fun parse(responseBody: String?): Hints {
        if (responseBody.isNullOrBlank()) return Hints()
        val errors = GraphQLErrorResponseParser.parseErrorsArray(responseBody) ?: return Hints()
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

        val argumentNameFromMessage = extractArgumentNameFromMessage(message)
        val fieldLocation = SchemaArgumentPathResolver.parseArgumentLocation(path, argumentNameFromMessage)
            ?: extensions?.let { ext ->
                val extField = ext.optString("fieldName").takeIf { it.isNotBlank() }
                val extArg = ext.optString("argumentName").takeIf { it.isNotBlank() }
                    ?: argumentNameFromMessage
                if (extField != null && extArg != null) extField to extArg else null
            }
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
        if (variableType in builtInScalars) return emptyList()
        return listOf(variableType to argumentType)
    }

    private val builtInScalars = setOf("String", "Int", "Float", "Boolean", "ID")

    private fun extractArgumentNameFromMessage(message: String): String? {
        val match = argumentMismatchMessage.find(message) ?: return null
        return match.groups["argument"]?.value?.trim()
    }

    private fun extractArgumentTypeFromMessage(message: String): String? {
        val match = argumentMismatchMessage.find(message) ?: return null
        return match.groups["argumentType"]?.value?.trim()
    }
}
