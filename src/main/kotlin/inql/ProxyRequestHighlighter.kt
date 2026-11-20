package inql

import burp.Burp
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.core.Registration
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.graphql.Utils

/**
 * Highlights GraphQL requests in Burp's Proxy history and annotates them with the operation name.
 *
 * Implemented as a Montoya [ProxyRequestHandler]: each request is inspected once, as it passes through the
 * proxy (after any Intercept edits), and the annotations are attached via [ProxyRequestToBeSentAction.continueWith].
 * There is no polling of the proxy history and no background queue.
 */
class ProxyRequestHighlighter private constructor() : ProxyRequestHandler {
    companion object {
        /** Requests with bodies larger than this are not parsed inline on the proxy thread. */
        private const val MAX_INLINE_BODY_BYTES = 1024 * 1024

        // Written by the lifecycle thread (extension load, settings hook, unload), read by Burp's proxy threads.
        @Volatile
        private var instance: ProxyRequestHighlighter? = null

        @Synchronized
        fun start() {
            if (instance != null) {
                Logger.warning("Proxy Request Highlighter is already running")
                return
            }
            instance = ProxyRequestHighlighter()
        }

        @Synchronized
        fun stop() {
            instance?.stop()
            instance = null
        }
    }

    private val color: HighlightColor =
        HighlightColor.highlightColor(Config.getInstance().getString("proxy.highlight_color"))
    private val gson = Gson()
    private val registration: Registration = Burp.Montoya.proxy().registerRequestHandler(this)

    init {
        Logger.debug("Proxy Request Highlighter started")
    }

    private fun stop() {
        registration.deregister()
        Logger.debug("Proxy Request Highlighter stopped")
    }

    override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest)
    }

    /**
     * Annotates at the "to be sent" stage, i.e. after any edits made in Proxy > Intercept, so the highlight and the
     * operation name match the request that actually went to the server.
     */
    override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
        val annotations = try {
            annotate(interceptedRequest)
        } catch (e: Exception) {
            // Never let an exception escape into Burp's proxy pipeline.
            Logger.warning("Proxy Request Highlighter failed to process a request: ${e.message}")
            null
        }
        return if (annotations != null) {
            ProxyRequestToBeSentAction.continueWith(interceptedRequest, annotations)
        } else {
            ProxyRequestToBeSentAction.continueWith(interceptedRequest)
        }
    }

    private fun annotate(request: InterceptedRequest): burp.api.montoya.core.Annotations? {
        if (request.body().length() > MAX_INLINE_BODY_BYTES) return null
        if (!Utils.mightBeGraphQLRequest(request)) return null
        if (!Utils.isGraphQLRequest(request)) return null

        val operationName = try {
            this.gson.fromJson(request.bodyToString(), JsonObject::class.java)
                ?.get("operationName")
                ?.takeIf { it.isJsonPrimitive }
                ?.asString
        } catch (_: Exception) {
            null
        }
        val note = if (operationName.isNullOrEmpty()) "GraphQL" else "GraphQL: $operationName"

        val annotations = request.annotations().withHighlightColor(this.color)
        // Don't overwrite notes added by the user or by another extension.
        return if (annotations.notes().isNullOrEmpty()) annotations.withNotes(note) else annotations
    }
}
