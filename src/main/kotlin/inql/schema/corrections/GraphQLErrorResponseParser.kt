package inql.schema.corrections

import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONArray
import org.json.JSONObject

/**
 * Reads `errors[].message` strings from standard GraphQL HTTP response bodies.
 */
object GraphQLErrorResponseParser {
    private val gson = Gson()

    fun errorMessages(responseBody: String?): List<String> {
        if (responseBody.isNullOrBlank()) return emptyList()
        val errors = parseErrors(responseBody) ?: return emptyList()
        return buildList {
            for (index in 0 until errors.length()) {
                val error = errors.optJSONObject(index) ?: continue
                error.optString("message", "").trim().takeIf { it.isNotEmpty() }?.let { add(it) }
            }
        }
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
