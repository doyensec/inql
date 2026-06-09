package inql.history

import org.json.JSONArray
import org.json.JSONObject

internal object ResponseDataParser {
    fun extractData(responseBody: String?): Map<String, Any?>? {
        if (responseBody.isNullOrBlank()) return null
        return try {
            val root = JSONObject(responseBody)
            val data = root.optJSONObject("data") ?: return null
            jsonObjectToMap(data)
        } catch (_: Exception) {
            null
        }
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
