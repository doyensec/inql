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
                    JsonKotlinBridge.jsonObjectToMap(data)
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
            return JsonKotlinBridge.jsonObjectToMap(data)
        }
        return null
    }

    fun responseValueForField(parent: Any?, fieldName: String, alias: String?): Any? {
        if (parent == null) return null
        val key = alias ?: fieldName
        return (parent as? Map<*, *>)?.get(key)
    }

    fun extractTypename(node: Any?): String? {
        val normalized = normalizeResponseNode(node) ?: return null
        return (normalized as? Map<*, *>)?.get("__typename") as? String
    }

    fun normalizeResponseNode(node: Any?): Any? {
        return when (node) {
            null -> null
            is JSONArray -> if (node.length() == 0) null else normalizeResponseNode(node.opt(0))
            is List<*> -> node.firstOrNull()?.let { normalizeResponseNode(it) }
            is JSONObject -> JsonKotlinBridge.jsonObjectToMap(node)
            is Map<*, *> -> node
            else -> node
        }
    }
}
