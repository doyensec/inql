package inql.externaltools

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.*
import inql.InQL
import inql.Logger
import inql.graphql.Utils.Companion.getGraphQLQuery
import inql.scanner.IntrospectionCache
import inql.utils.get
import inql.utils.withUpsertedHeader

class ExternalToolsRequestFixer(val inql: InQL, val webServerPort: Int): ProxyRequestHandler, ProxyResponseHandler {
    companion object {
        const val INTERNAL_INQL_HOST = "inql.burp"
        const val INTERNAL_INQL_ORIGIN = "https://$INTERNAL_INQL_HOST"
        const val INQL_HEADER = "Inql"

        private fun isIntrospectionRequest(request: InterceptedRequest): Boolean {
            val query = getGraphQLQuery(request) ?: return false

            // The value of "query" contains "__schema"
            // TODO: Replace this with proper parsing of the GraphQL request
            if (!query.contains("__schema")) {
                return false
            }

            Logger.debug("Introspection query validated!")
            return true
        }

        private fun fixCORSHeaders(request: HttpRequest, response: HttpResponse): HttpResponse {
            val origin = request.headers().get("Origin") ?: INTERNAL_INQL_ORIGIN
            val allowedMethods = request.headers().get("Access-Control-Request-Method") ?: "GET, PATCH, POST, OPTIONS"
            val allowedHeaders = request.headers().get("Access-Control-Request-Headers") ?: "Content-Type, InQL"

            return response
                .withUpsertedHeader("Access-Control-Allow-Origin", origin)
                .withUpsertedHeader("Access-Control-Allow-Methods", allowedMethods)
                .withUpsertedHeader("Access-Control-Allow-Headers", allowedHeaders)
                .withUpsertedHeader("Access-Control-Allow-Credentials", "true")
                .withUpsertedHeader("Vary", "Origin")
        }
    }

    private val corsRequests = HashSet<Int>()
    private val introspectionRequests = HashMap<Int, String>()

    // Part of ProxyRequestHandler interface, executed first on every request coming through Burp's Proxy tool
    override fun handleRequestReceived(request: InterceptedRequest): ProxyRequestReceivedAction {
        return ProxyRequestReceivedAction.continueWith(request)
    }

    // Part of ProxyRequestHandler interface, leave it alone
    override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
        // Request to internal server: forward to correct port
        if (interceptedRequest.httpService().host() == INTERNAL_INQL_HOST) {
            val service = HttpService.httpService("127.0.0.1", webServerPort, false)
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest.withService(service))
        }

        // Request to external world

        // Let request go through if not from internal web server
        if (interceptedRequest.headers().get("Origin") != INTERNAL_INQL_ORIGIN) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
        }

        // All requests after this point come from the internal web server

        // If OPTIONS redirect request and send CORS in response
        // If POST request, mark the request to be CORS-fixed BUT don't return early,
        // as more transformations may need to be applied to it
        if (interceptedRequest.method() == "OPTIONS") {
            this.corsRequests.add(interceptedRequest.messageId())
            return ProxyRequestToBeSentAction.continueWith(this.sendToDummy(interceptedRequest))
        } else if (interceptedRequest.method() == "POST") {
            this.corsRequests.add(interceptedRequest.messageId())
        }

        // If it's a GraphQL introspection request, mark the response to be intercepted and redirect to dummy page
        if (isIntrospectionRequest(interceptedRequest)) {
            Logger.debug("Potential introspection request detected")
            val schema = getSchemaForRequest(interceptedRequest)
            if (schema != null) {
                Logger.debug("Found cached schema for this request: $schema")
                this.introspectionRequests[interceptedRequest.messageId()] = schema
                return ProxyRequestToBeSentAction.continueWith(this.sendToDummy(interceptedRequest))
            }
        }

        // Has our proprietary `InQL` header holding the session identifier
        if (interceptedRequest.headers().get(INQL_HEADER) != null) {
            Logger.debug("Request with InQL header")

            // TODO: add logic here to add headers and variables

            return ProxyRequestToBeSentAction.continueWith(interceptedRequest.withRemovedHeader(INQL_HEADER))
        }

        // Otherwise just forward request
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
    }

    private fun sendToDummy(request: HttpRequest): HttpRequest {
        val service = HttpService.httpService("127.0.0.1", webServerPort, false)
        var req = HttpRequest.httpRequest()
            .withService(service)
            .withMethod(request.method())
            .withPath("/dummy")
            .withBody("")
            .withUpsertedHeader("Origin", request.headers().get("Origin") ?: INTERNAL_INQL_ORIGIN)

        for (header in request.headers()) {
            if (header.name().lowercase().startsWith("access-")) {
                req = req.withAddedHeader(header)
            }
        }

        return req
    }

    private fun getSchemaForRequest(interceptedRequest: InterceptedRequest): String? {
        var profileName = interceptedRequest.headers().get(INQL_HEADER)
        if (profileName == null || profileName.lowercase() == "default") profileName = IntrospectionCache.NO_PROFILE
        Logger.debug("Searching cached schema with the following details: ${interceptedRequest.url()} | $profileName")
        return this.inql.scanner.introspectionCache.get(interceptedRequest.url(), profileName)?.rawSchema
    }

    override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
        return ProxyResponseReceivedAction.continueWith(interceptedResponse)
    }

    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
        var response: HttpResponse = interceptedResponse
        val msgId = interceptedResponse.messageId()

        // Fix CORS if marked
        if (this.corsRequests.contains(msgId)) {
            response = fixCORSHeaders(interceptedResponse.initiatingRequest(), response)
            this.corsRequests.remove(msgId)
        }

        // Reply with introspection if marked
        if (this.introspectionRequests.containsKey(msgId)) {
            response = response
                .withBody(this.introspectionRequests[msgId])
                .withUpsertedHeader("Content-Type", "application/json")
            this.introspectionRequests.remove(msgId)
        }

        return ProxyResponseToBeSentAction.continueWith(response)
    }
}