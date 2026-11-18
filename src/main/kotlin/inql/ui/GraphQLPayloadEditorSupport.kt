package inql.ui

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonSyntaxException
import inql.graphql.GraphQLRequestContext
import inql.graphql.GraphQLRequestPayload
import inql.graphql.GraphQLRequestTransformer
import inql.graphql.GraphQLTransportFormat
import java.net.URI

data class LoadedGraphQLPayload(
    val payload: GraphQLRequestPayload,
    val context: GraphQLRequestContext,
) {
    val query: String get() = payload.query
    val variables: JsonObject? get() = GraphQLPayloadEditorSupport.variablesToJsonObject(payload.variables)
    val operationName: String? get() = payload.operationName
    val isBatch: Boolean get() = payload.isBatch
}

/**
 * Tracks the GraphQL transport encoding (JSON, GET, multipart, etc.) for the Repeater
 * message editor. Burp reuses one editor instance across tabs, so we key state by
 * transport fingerprint and only keep in-flight edits when the wire encoding is unchanged.
 */
class GraphQLRequestEditorTransportState {
    var request: HttpRequest? = null
    private var transportBaseRequest: HttpRequest? = null
    private var lockedContext: GraphQLRequestContext? = null
    private var wireTransportKey: String? = null
    var skipNextSetRequestResponse = false

    fun onSetRequestResponse(
        incoming: HttpRequest,
        isModified: Boolean,
        onLoad: (LoadedGraphQLPayload) -> Unit,
        onParseError: () -> Unit,
    ) {
        if (skipNextSetRequestResponse) {
            skipNextSetRequestResponse = false
            adoptIncomingTransport(incoming)
            return
        }

        val loaded = GraphQLPayloadEditorSupport.loadFromRequest(incoming)
        if (loaded == null) {
            onParseError()
            return
        }

        val incomingKey = transportKey(incoming, loaded.context)
        val encodingChanged = wireTransportKey != null && wireTransportKey != incomingKey

        if (isModified) {
            if (!encodingChanged) {
                return
            }
            if (isGetJsonProjection(transportBaseRequest, incoming)) {
                return
            }
        }

        request = incoming
        transportBaseRequest = incoming
        lockedContext = loaded.context
        wireTransportKey = incomingKey
        onLoad(loaded)
    }

    fun buildRequest(payload: GraphQLRequestPayload): HttpRequest {
        val context = lockedContext
            ?: transportBaseRequest?.let { GraphQLRequestTransformer.detectRequestContext(it) }
            ?: GraphQLRequestContext(GraphQLTransportFormat.JSON)

        val built = GraphQLPayloadEditorSupport.buildRequest(
            baseRequest = transportBaseRequest ?: request ?: HttpRequest.httpRequest(),
            context = context,
            payload = payload,
        )
        skipNextSetRequestResponse = true
        request = built
        transportBaseRequest = built
        lockedContext = context
        wireTransportKey = transportKey(built, context)
        return built
    }

    private fun adoptIncomingTransport(incoming: HttpRequest) {
        request = incoming
        transportBaseRequest = incoming
        lockedContext = GraphQLRequestTransformer.detectRequestContext(incoming)
        wireTransportKey = transportKey(incoming, lockedContext!!)
    }

    private fun transportKey(request: HttpRequest, context: GraphQLRequestContext): String {
        val path = URI.create(request.url()).rawPath ?: "/"
        val boundary = context.multipartBoundary ?: ""
        val batchMarker = if (GraphQLRequestTransformer.parsePayload(request)?.isBatch == true) "|batch" else ""
        return "${request.method()}|$path|${context.format}|$boundary$batchMarker"
    }

    private fun isGetJsonProjection(base: HttpRequest?, incoming: HttpRequest): Boolean {
        if (base == null) return false
        val baseContext = lockedContext ?: GraphQLRequestTransformer.detectRequestContext(base)
        if (baseContext.format != GraphQLTransportFormat.GET) {
            return false
        }
        val incomingContext = GraphQLRequestTransformer.detectRequestContext(incoming)
        if (incomingContext.format != GraphQLTransportFormat.JSON) {
            return false
        }
        return GraphQLRequestTransformer.payloadsEqual(base, incoming)
    }
}

object GraphQLPayloadEditorSupport {
    private val gson = Gson()

    fun loadFromRequest(request: HttpRequest): LoadedGraphQLPayload? {
        val payload = GraphQLRequestTransformer.parsePayload(request) ?: return null
        val context = GraphQLRequestTransformer.detectRequestContext(request)
        return LoadedGraphQLPayload(payload = payload, context = context)
    }

    fun buildRequest(
        baseRequest: HttpRequest,
        context: GraphQLRequestContext,
        payload: GraphQLRequestPayload,
    ): HttpRequest {
        return GraphQLRequestTransformer.applyPayload(baseRequest, payload, context)
    }

    fun variablesToJsonObject(variables: String?): JsonObject? {
        if (variables == null || variables == "null") return null
        return try {
            gson.fromJson(variables, JsonObject::class.java)
        } catch (_: JsonSyntaxException) {
            null
        }
    }
}
