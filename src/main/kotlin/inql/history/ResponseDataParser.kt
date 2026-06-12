package inql.history

import org.json.JSONArray
import org.json.JSONObject

internal object ResponseDataParser {
    fun extractData(responseBody: String?): Map<String, Any?>? {
        if (responseBody.isNullOrBlank()) return null
        val trimmed = responseBody.trim()
        return try {
            when {
                trimmed.startsWith("[") -> extractDataFromBatch(trimmed)
                else -> {
                    val root = JSONObject(trimmed)
                    val data = root.optJSONObject("data") ?: return null
                    jsonObjectToMap(data)
                }
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractDataFromBatch(responseBody: String): Map<String, Any?>? {
        val array = JSONArray(responseBody)
        for (index in 0 until array.length()) {
            val entry = array.optJSONObject(index) ?: continue
            val data = entry.optJSONObject("data") ?: continue
            return jsonObjectToMap(data)
        }
        return null
    }

    fun responseValueForField(parent: Any?, fieldName: String, alias: String?): Any? {
        if (parent == null) return null
        val key = alias ?: fieldName
        return when (parent) {
            is Map<*, *> -> parent[key]
            is JSONObject -> parent.opt(key)
            else -> null
        }
    }

    fun extractTypename(node: Any?): String? {
        val normalized = normalizeResponseNode(node) ?: return null
        return when (normalized) {
            is Map<*, *> -> normalized["__typename"] as? String
            is JSONObject -> normalized.optString("__typename").takeIf { it.isNotBlank() }
            else -> null
        }
    }

    fun normalizeResponseNode(node: Any?): Any? {
        return when (node) {
            null -> null
            is JSONArray -> if (node.length() == 0) null else normalizeResponseNode(node.opt(0))
            is List<*> -> node.firstOrNull()?.let { normalizeResponseNode(it) }
            is JSONObject -> jsonObjectToMap(node)
            is Map<*, *> -> node
            else -> node
        }
    }

    private fun jsonObjectToMap(jsonObject: JSONObject): Map<String, Any?> {
        val map = linkedMapOf<String, Any?>()
        for (key in jsonObject.keys()) {
            map[key] = jsonValueToKotlin(jsonObject.get(key))
        }
        return map
    }

    private fun jsonValueToKotlin(value: Any?): Any? {
        return when (value) {
            null, JSONObject.NULL -> null
            is JSONObject -> jsonObjectToMap(value)
            is JSONArray -> (0 until value.length()).map { index ->
                jsonValueToKotlin(value.opt(index))
            }
            else -> value
        }
    }
}
