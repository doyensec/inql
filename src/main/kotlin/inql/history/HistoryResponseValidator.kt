package inql.history

import inql.schema.corrections.GraphQLErrorResponseParser
import org.json.JSONArray

object HistoryResponseValidator {
    private val schemaRejectionPatterns = listOf(
        Regex("""Cannot query field ['"`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)['"`]?""", RegexOption.IGNORE_CASE),
        Regex("""Field ['"`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)['"`]? doesn't exist on type""", RegexOption.IGNORE_CASE),
        Regex("""Field ['"](?<field>[^'"]+)['"].*undefined""", RegexOption.IGNORE_CASE),
    )

    private val applicationErrorKeywords = listOf(
        "forbidden",
        "unauthorized",
        "rate limit",
    )

    fun getRejectedFieldNames(responseBody: String): Set<String> {
        val rejected = mutableSetOf<String>()
        val errors = GraphQLErrorResponseParser.parseErrorsArray(responseBody) ?: return rejected

        for (i in 0 until errors.length()) {
            val error = errors.optJSONObject(i) ?: continue
            val message = error.optString("message", "")
            if (isApplicationLevelError(message)) continue
            rejected.addAll(extractRejectedFields(message))
            error.optJSONObject("extensions")?.optString("fieldName")
                ?.takeIf { it.isNotBlank() }
                ?.let { rejected.add(it) }
        }
        return rejected
    }

    fun hasOnlyApplicationLevelErrors(responseBody: String): Boolean {
        val errors = GraphQLErrorResponseParser.parseErrorsArray(responseBody) ?: return false
        if (errors.length() == 0) return false

        for (i in 0 until errors.length()) {
            val error = errors.optJSONObject(i) ?: continue
            val message = error.optString("message", "")
            if (!isApplicationLevelError(message) && isSchemaRejectionError(message)) {
                return false
            }
        }
        return true
    }

    private fun isApplicationLevelError(message: String): Boolean {
        val lower = message.lowercase()
        return applicationErrorKeywords.any { lower.contains(it) }
    }

    private fun isSchemaRejectionError(message: String): Boolean {
        val lower = message.lowercase()
        return lower.contains("cannot query field") ||
            lower.contains("doesn't exist on type") ||
            lower.contains("field undefined")
    }

    private fun extractRejectedFields(message: String): Set<String> {
        val fields = mutableSetOf<String>()
        for (pattern in schemaRejectionPatterns) {
            pattern.findAll(message).forEach { match ->
                match.groups["field"]?.value?.let { fields.add(it) }
            }
        }
        return fields
    }
}
