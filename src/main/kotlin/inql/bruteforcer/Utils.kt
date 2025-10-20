// inql/bruteforcer/Utils.kt
package inql.bruteforcer

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.exceptions.BlankResponseException
import inql.exceptions.TooManyRequestsException // Add this import
import org.json.JSONObject

class Utils {
    companion object {
        fun sendGraphQLRequest(query: String, request: HttpRequest): JSONObject {
            // No try-catch here anymore, we let the client handle it
            val newQuery = JsonObject()
            newQuery.addProperty("query", query)
            val newBody = Gson().toJson(newQuery)
            val req =
                request.withService(burp.api.montoya.http.HttpService.httpService(request.url())).withBody(newBody)
            val response = Burp.Montoya.http().sendRequest(req) ?: throw BlankResponseException()
            val resp = response.response() ?: throw BlankResponseException()

            if (resp.statusCode().toInt() == 429) {
                throw TooManyRequestsException("Server responded with 429 Too Many Requests")
            }

            return JSONObject(resp.body().toString())
        }
    }
}