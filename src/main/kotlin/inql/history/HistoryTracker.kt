package inql.history

import burp.Burp
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import graphql.schema.GraphQLSchema
import inql.Config
import inql.InQL
import inql.Logger
import inql.graphql.Utils
import inql.schema.corrections.SchemaCorrections
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel

/**
 * Learns GraphQL schemas from traffic passing through Burp's proxy.
 *
 * Implemented as a Montoya [ProxyResponseHandler]: every completed request/response pair is delivered by Burp as
 * it arrives, so there is no polling of the proxy history. The handler itself only runs cheap checks (tracking
 * enabled, scope, a byte-level GraphQL pre-filter) and hands candidate items to a bounded queue; parsing and
 * schema building happen on a background coroutine.
 */
class HistoryTracker private constructor(private val inql: InQL) : ProxyResponseHandler {
    companion object {
        /** Maximum number of pending items. Under sustained load the oldest pending items are dropped. */
        private const val QUEUE_CAPACITY = 1_000

        // Written by the lifecycle thread (start/stop), read by Burp's proxy and UI threads.
        @Volatile
        private var instance: HistoryTracker? = null

        /** Set on extension unload; a late start() (e.g. from a still-running project load) must not register again. */
        @Volatile
        private var shutDown = false

        @Synchronized
        fun start(inql: InQL) {
            if (shutDown) {
                Logger.debug("Extension is unloading, not starting the history tracker")
                return
            }
            val old = instance
            // Clear first so a failing constructor doesn't leave a stopped tracker that still reports isRunning().
            instance = null
            old?.stop()
            instance = HistoryTracker(inql)
        }

        @Synchronized
        fun stop() {
            val old = instance
            instance = null
            old?.stop()
        }

        /** Stops the tracker for good. Called from extension unload. */
        @Synchronized
        fun shutdown() {
            shutDown = true
            stop()
        }

        fun extractSchemaForHost(host: String) {
            instance?.extractSchemaForHost(host)
        }

        fun storeCorrections(host: String, corrections: SchemaCorrections, schema: GraphQLSchema) {
            instance?.schemaService?.storeCorrections(host, corrections, schema)
        }

        fun isRunning(): Boolean = instance != null

        fun releaseHostIfNoOpenTabs(host: String) {
            instance?.schemaService?.releaseHostIfNoOpenTabs(host)
        }
    }

    private data class HistoryItem(val request: HttpRequest, val response: HttpResponse)

    private val processingScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val schemaService = HistorySchemaService(inql)
    private val historyItemChannel = Channel<HistoryItem>(
        capacity = QUEUE_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    private val registration: Registration

    init {
        processingScope.launch { processHistoryQueue() }
        registration = Burp.Montoya.proxy().registerResponseHandler(this)
        Logger.debug("History tracker started")
    }

    private fun stop() {
        try {
            registration.deregister()
        } finally {
            historyItemChannel.close()
            processingScope.cancel()
            schemaService.stop()
            Logger.debug("History tracker stopped")
        }
    }

    override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
        try {
            enqueueIfRelevant(interceptedResponse)
        } catch (e: Exception) {
            // Never let an exception escape into Burp's proxy pipeline.
            Logger.warning("History tracker failed to queue a proxy item: ${e.message}")
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse)
    }

    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
    }

    private fun enqueueIfRelevant(interceptedResponse: InterceptedResponse) {
        val config = Config.getInstance()
        if (config.getBoolean("history.tracking_enabled") != true) return

        val request = interceptedResponse.initiatingRequest()
        if (config.getBoolean("history.in_scope_only") == true && !Burp.Montoya.scope().isInScope(request.url())) return
        if (!Utils.mightBeGraphQLRequest(request)) return

        // Copy both messages so the queued item doesn't hold on to Burp's intercepted message objects.
        val requestCopy = HttpRequest.httpRequest(request.httpService(), request.toByteArray())
        val response = HttpResponse.httpResponse(interceptedResponse.toByteArray())
        historyItemChannel.trySend(HistoryItem(requestCopy, response))
    }

    private suspend fun processHistoryQueue() {
        for (item in historyItemChannel) {
            try {
                handleHistoryItem(item)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                // Keep the consumer alive: one malformed item (even a StackOverflowError from a deeply nested
                // document) must not silently stop schema learning.
                Logger.warning("History tracker failed to process a proxy item: ${e.message}")
            }
            yield()
        }
    }

    fun extractSchemaForHost(host: String) {
        schemaService.extractSchemaForHost(host)
    }

    private suspend fun handleHistoryItem(item: HistoryItem) {
        if (Utils.getGraphQLOperations(item.request).isEmpty()) return
        schemaService.processRequest(item.request, item.response)
    }
}
