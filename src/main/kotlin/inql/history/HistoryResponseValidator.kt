package inql.history

import burp.api.montoya.http.message.responses.HttpResponse
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONArray
import org.json.JSONObject

object HistoryResponseValidator {
    private val gson = Gson()

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

    fun isSuccessfulResponse(response: HttpResponse?): Boolean {
        return response?.statusCode()?.toInt() == 200
    }

    fun isSuccessfulResponseBody(responseBody: String): Boolean {
        return try {
            val json = gson.fromJson(responseBody, JsonObject::class.java)
            !json.has("errors") || json.getAsJsonArray("errors").isEmpty
        } catch (_: Exception) {
            try {
                val jsonObject = JSONObject(responseBody)
                !jsonObject.has("errors") || jsonObject.optJSONArray("errors")?.length() == 0
            } catch (_: Exception) {
                true
            }
        }
    }

    fun getRejectedFieldNames(responseBody: String): Set<String> {
        val rejected = mutableSetOf<String>()
        val errors = parseErrors(responseBody) ?: return rejected

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
        val errors = parseErrors(responseBody) ?: return false
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

    private fun parseErrors(responseBody: String): JSONArray? {
        if (responseBody.isBlank()) return null
        val trimmed = responseBody.trim()
        if (trimmed.startsWith("[")) {
            return parseBatchErrors(trimmed)
        }
        return try {
            val json = gson.fromJson(trimmed, JsonObject::class.java)
            when {
                json.has("errors") -> JSONArray(json.getAsJsonArray("errors").toString())
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
