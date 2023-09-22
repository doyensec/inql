package inql.utils

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonElement

class GraphQL {
    companion object {
        fun isGraphQLQuery(s: String): Boolean {
            return try {
                var elem = Gson().fromJson<JsonElement>(s, JsonElement::class.java)
                if (!elem.isJsonArray) elem = JsonArray(1).also { it.add(elem) }
                elem.asJsonArray.all { it.asJsonObject.has("query") }
            } catch (e: Exception) {
                false
            }
        }
    }
}
