package inql.history

import org.json.JSONArray
import org.json.JSONObject

/** Converts org.json structures to Kotlin collections for response/variable parsing. */
internal object JsonKotlinBridge {
    fun jsonObjectToMap(jsonObject: JSONObject): Map<String, Any?> {
        val map = linkedMapOf<String, Any?>()
        for (key in jsonObject.keys()) {
            map[key] = jsonValueToKotlin(jsonObject.get(key))
        }
        return map
    }

    fun jsonValueToKotlin(value: Any?): Any? {
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
