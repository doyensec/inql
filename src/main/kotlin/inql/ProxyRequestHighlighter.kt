package inql

import burp.Burp
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.graphql.Utils
import kotlinx.coroutines.*


class ProxyRequestHighlighter private constructor(){
    companion object {
        private lateinit var instance: ProxyRequestHighlighter
        public fun start() {
            if (!this::instance.isInitialized) {
                this.instance = ProxyRequestHighlighter()
            } else {
                Logger.error("Cannot start Request Highlighter more than once, something's wrong")
                throw Exception("Cannot start Request Highlighter more than once, something's wrong")
            }
        }

        public fun stop() {
            if (this::instance.isInitialized) this.instance.stop()
        }
    }

    private var pollingDelay = 1000L // 1 sec
    private val color: HighlightColor = HighlightColor.highlightColor(Config.getInstance().getString("proxy.highlight_color"))
    private val pollingScope = CoroutineScope(Dispatchers.IO)
    private val coroutineScope = CoroutineScope(Dispatchers.Default)
    private val gson = Gson()

    private var oldIdx = 0
    private val newIdx = {
        Burp.Montoya.proxy().history().size - 1
    }

    init {
        this.oldIdx = this.newIdx()

        this.pollingScope.launch {
            this@ProxyRequestHighlighter.poll()
        }

        Logger.debug("Proxy Request Highlighter started")
    }

    private fun stop() {
        this.pollingScope.cancel()
        this.coroutineScope.cancel()
    }
    private suspend fun poll() {
        while (true) {
            delay(this.pollingDelay)

            val newIdx = this.newIdx()
            // If no new requests have arrived, skip a cycle
            if (newIdx == this.oldIdx) continue

            // Else, spawn a coroutine for each new requests
            Logger.debug("Spawning coroutines for requests ${this.oldIdx+1}-$newIdx")
            for (idx in this.oldIdx+1..newIdx) {
                this.coroutineScope.launch { this@ProxyRequestHighlighter.handleRequest(Burp.Montoya.proxy().history()[idx]) }
            }
            this.oldIdx = newIdx
        }
    }

    private fun handleRequest(req: ProxyHttpRequestResponse) {
        if (!Utils.isGraphQLRequest(req.finalRequest())) return

        req.annotations().setHighlightColor(this.color)
        var operationName: String? = null
        try {
            operationName = this.gson.fromJson(req.finalRequest().bodyToString(), JsonObject::class.java).get("operationName").asString
        } catch (_: Exception) {
            // Do nothing
        }

        val note: String = if (operationName.isNullOrEmpty()) {
            "GraphQL"
        } else {
            "GraphQL: $operationName"
        }

        req.annotations().setNotes(note)
    }

}