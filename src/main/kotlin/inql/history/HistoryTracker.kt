package inql.history

import burp.Burp
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import graphql.schema.GraphQLSchema
import inql.Config
import inql.InQL
import inql.Logger
import inql.graphql.Utils
import inql.schema.corrections.SchemaCorrections
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel

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

        fun storeCorrections(host: String, corrections: SchemaCorrections, schema: GraphQLSchema) {
            if (this::instance.isInitialized) {
                instance.schemaService.storeCorrections(host, corrections, schema)
            }
        }

        fun resetHostSchema(host: String) {
            if (this::instance.isInitialized) {
                instance.schemaService.resetHostForReextract(host)
            }
        }

        fun isRunning(): Boolean = this::instance.isInitialized

        fun releaseHostIfNoOpenTabs(host: String) {
            if (this::instance.isInitialized) {
                instance.schemaService.releaseHostIfNoOpenTabs(host)
            }
        }
    }

    private val pollingDelay = 1000L
    private val pollingScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val processingScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val schemaService = HistorySchemaService(inql)
    private val historyItemChannel = Channel<ProxyHttpRequestResponse>(Channel.UNLIMITED)

    private var oldIdx = 0
    private val newIdx = { Burp.Montoya.proxy().history().size - 1 }

    init {
        oldIdx = newIdx()
        pollingScope.launch { poll() }
        processingScope.launch { processHistoryQueue() }
        Logger.debug("History tracker started")
    }

    private fun stop() {
        pollingScope.cancel()
        processingScope.cancel()
        historyItemChannel.close()
        schemaService.stop()
        Logger.debug("History tracker stopped")
    }

    private suspend fun processHistoryQueue() {
        for (item in historyItemChannel) {
            handleHistoryItem(item)
            yield()
        }
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

            for (idx in oldIdx + 1..currentIdx) {
                historyItemChannel.send(Burp.Montoya.proxy().history()[idx])
            }
            oldIdx = currentIdx
        }
    }

    private suspend fun handleHistoryItem(item: ProxyHttpRequestResponse) {
        val request = item.finalRequest()
        if (Utils.getGraphQLOperations(request).isEmpty()) return

        val response = item.originalResponse()
        if (response != null) {
            schemaService.processRequest(request, response)
        } else {
            schemaService.processRequest(request)
        }
    }
}
