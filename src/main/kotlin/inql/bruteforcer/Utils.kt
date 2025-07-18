package inql.bruteforcer

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONObject

class Utils {
    companion object {
        fun sendGraphQLRequest(query: String, request: HttpRequest): JSONObject {
            try {
                val newQuery = JsonObject()
                newQuery.addProperty("query", query)
                val newBody = Gson().toJson(newQuery)
                val req =
                    request.withService(burp.api.montoya.http.HttpService.httpService(request.url())).withBody(newBody)
                val response = Burp.Montoya.http().sendRequest(req)
                val resp = response.response()

                return JSONObject(resp.body().toString())
            } catch (e: Exception) {
                return JSONObject()
            }
        }
    }
}