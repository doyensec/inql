// inql/bruteforcer/ThrottledGraphQLClient.kt
package inql.bruteforcer

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import inql.Logger
import inql.exceptions.BlankResponseException
import inql.exceptions.TooManyRequestsException
import kotlinx.coroutines.delay
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

class ThrottledClient(private val baseRequest: HttpRequest) {
    private val backoffDelay = AtomicLong(0L)
    private val INITIAL_BACKOFF_MS = 1000L
    private val MAX_BACKOFF_MS = 60000L

    /**
     * Sends a GraphQL query with an exponential backoff and retry mechanism
     * for handling 429 Too Many Requests errors.
     */
    suspend fun send(query: String): JSONObject {
        while (true) {
            awaitBackoff()
            try {
                val response = Utils.sendGraphQLRequest(query, baseRequest)
                resetBackoff()
                return response
            } catch (e: TooManyRequestsException) {
                increaseBackoff()
            } catch (e: BlankResponseException) {
                increaseBackoff()
            } catch (e: Exception) {
                Logger.error("An unexpected error occurred during the request: ${e.message}")
                return JSONObject()
            }
        }
    }

    /**
     * Sends an arbitrary HTTP request with the same backoff/retry behavior as [send].
     */
    suspend fun sendRequest(request: HttpRequest): HttpResponse? {
        while (true) {
            awaitBackoff()
            try {
                val response = Burp.Montoya.http().sendRequest(request)?.response()
                    ?: throw BlankResponseException()
                if (response.statusCode().toInt() == 429) {
                    throw TooManyRequestsException("Server responded with 429 Too Many Requests")
                }
                resetBackoff()
                return response
            } catch (e: TooManyRequestsException) {
                increaseBackoff()
            } catch (e: BlankResponseException) {
                increaseBackoff()
            } catch (e: Exception) {
                Logger.error("An unexpected error occurred during the request: ${e.message}")
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
