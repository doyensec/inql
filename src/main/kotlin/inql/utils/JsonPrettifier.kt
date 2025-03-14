package inql.utils

import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import inql.Logger

class JsonPrettifier {
    companion object {
        fun prettify(src: String): String {
            var json = src
            try {
                val gson = GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create()
                val je = JsonParser.parseString(json)
                json = gson.toJson(je)
            } catch (_: Exception) {
                Logger.debug("Failed to pretty print JSON schema")
            }
            return json
        }
    }
}
