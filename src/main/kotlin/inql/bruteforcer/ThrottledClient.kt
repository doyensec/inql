// inql/bruteforcer/ThrottledGraphQLClient.kt
package inql.bruteforcer

import burp.api.montoya.http.message.requests.HttpRequest
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
            val currentDelay = backoffDelay.get()
            if (currentDelay > 0) {
                delay(currentDelay)
            }

            try {
                val response = Utils.sendGraphQLRequest(query, baseRequest)

                if (backoffDelay.get() > 0) {
                    backoffDelay.set(0L)
                }
                return response

            } catch (e: TooManyRequestsException) {
                val current = backoffDelay.get()
                val newDelay = if (current == 0L) {
                    INITIAL_BACKOFF_MS
                } else {
                    (current * 2).coerceAtMost(MAX_BACKOFF_MS)
                }
                backoffDelay.set(newDelay)

            } catch (e: BlankResponseException) {
                val current = backoffDelay.get()
                val newDelay = if (current == 0L) {
                    INITIAL_BACKOFF_MS
                } else {
                    (current * 2).coerceAtMost(MAX_BACKOFF_MS)
                }
                backoffDelay.set(newDelay)
            } catch (e: Exception) {
                Logger.error("An unexpected error occurred during the request: ${e.message}")
                return JSONObject()
            }
        }
    }
}