package inql.bruteforcer

import burp.Burp
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.Logger
import inql.exceptions.BlankResponseException
import inql.exceptions.TooManyRequestsException
import inql.utils.withUpsertedHeader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.coroutineContext

class ThrottledClient(private val baseRequest: HttpRequest) {
    private val backoffDelay = AtomicLong(0L)
    private val INITIAL_BACKOFF_MS = 1000L
    private val MAX_BACKOFF_MS = 60000L
    private val MAX_RETRIES = 6

    var lastRequest: HttpRequest? = null
        private set
    var lastResponse: HttpResponse? = null
        private set

    suspend fun send(query: String): JSONObject {
        val payload = JsonObject()
        payload.addProperty("query", query)
        val req = baseRequest
            .withService(HttpService.httpService(baseRequest.url()))
            .withMethod("POST")
            .withUpsertedHeader("Content-Type", "application/json")
            .withBody(Gson().toJson(payload))
        val response = sendRequest(req) ?: return JSONObject()
        return try {
            JSONObject(response.bodyToString())
        } catch (_: Exception) {
            JSONObject()
        }
    }

    suspend fun sendRequest(request: HttpRequest): HttpResponse? {
        // Publish request/response only as a matched pair after a successful exchange.
        lastRequest = null
        lastResponse = null
        val response = withBackoff {
            val resp = Burp.Montoya.http().sendRequest(request)?.response()
                ?: throw BlankResponseException()
            if (resp.statusCode().toInt() == 429) {
                throw TooManyRequestsException("Server responded with 429 Too Many Requests")
            }
            resp
        }
        if (response != null) {
            lastRequest = request
            lastResponse = response
        }
        return response
    }

    private suspend fun <T> withBackoff(block: suspend () -> T): T? {
        var attempts = 0
        while (true) {
            coroutineContext.ensureActive()
            awaitBackoff()
            try {
                val result = block()
                resetBackoff()
                return result
            } catch (_: TooManyRequestsException) {
                increaseBackoff()
            } catch (_: BlankResponseException) {
                increaseBackoff()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Logger.error("An unexpected error occurred during the request: ${e.message}")
                return null
            }
            attempts++
            if (attempts >= MAX_RETRIES) {
                Logger.error("Giving up after $MAX_RETRIES throttled retries")
                return null
            }
        }
    }

    private suspend fun awaitBackoff() {
        val currentDelay = backoffDelay.get()
        if (currentDelay > 0) {
            delay(currentDelay)
        }
    }

    private fun resetBackoff() {
        if (backoffDelay.get() > 0) {
            backoffDelay.set(0L)
        }
    }

    private fun increaseBackoff() {
        val current = backoffDelay.get()
        val newDelay = if (current == 0L) {
            INITIAL_BACKOFF_MS
        } else {
            (current * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
        backoffDelay.set(newDelay)
    }
}
