package inql.history

import burp.Burp
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import inql.Config
import inql.InQL
import inql.Logger
import inql.graphql.Utils
import kotlinx.coroutines.*

class HistoryTracker private constructor(private val inql: InQL) {
    companion object {
        private lateinit var instance: HistoryTracker

        fun start(inql: InQL) {
            if (this::instance.isInitialized) {
                instance.stop()
            }
            instance = HistoryTracker(inql)
        }

        fun stop() {
            if (this::instance.isInitialized) {
                instance.stop()
            }
        }

        fun extractSchemaForHost(host: String) {
            if (this::instance.isInitialized) {
                instance.extractSchemaForHost(host)
            }
        }

        fun isRunning(): Boolean = this::instance.isInitialized
    }

    private val pollingDelay = 1000L
    private val pollingScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val processingScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val schemaService = HistorySchemaService(inql)

    private var oldIdx = 0
    private val newIdx = { Burp.Montoya.proxy().history().size - 1 }

    init {
        oldIdx = newIdx()
        pollingScope.launch { poll() }
        Logger.debug("History tracker started")
    }

    private fun stop() {
        pollingScope.cancel()
        processingScope.cancel()
        schemaService.stop()
        Logger.debug("History tracker stopped")
    }

    fun extractSchemaForHost(host: String) {
        schemaService.extractSchemaForHost(host)
    }

    private suspend fun poll() {
        while (true) {
            delay(pollingDelay)
            if (Config.getInstance().getBoolean("history.tracking_enabled") != true) continue

            val currentIdx = newIdx()
            if (currentIdx <= oldIdx) continue

            val batch = (oldIdx + 1..currentIdx).map { Burp.Montoya.proxy().history()[it] }
            oldIdx = currentIdx

            processingScope.launch {
                for (item in batch) {
                    handleHistoryItem(item)
                    yield()
                }
            }
        }
    }

    private fun handleHistoryItem(item: ProxyHttpRequestResponse) {
        val request = item.finalRequest()
        if (!Utils.isGraphQLRequest(request)) return

        val response = item.originalResponse()
        if (response != null) {
            schemaService.processRequestResponse(
                HttpRequestResponse.httpRequestResponse(request, response),
            )
        } else {
            schemaService.processRequest(request)
        }
    }
}
