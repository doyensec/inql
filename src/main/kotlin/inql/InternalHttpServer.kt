package inql

import burp.Burp
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.http.HttpService
import java.io.IOException
import java.net.ServerSocket
import java.util.Random
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.http.*
import io.ktor.server.http.content.*
import io.ktor.server.request.*

import java.awt.EventQueue
import javax.swing.SwingUtilities
import javax.swing.JFrame

/*
    This file defines embedded HTTP server with the following functionality:

        1. Serving web based GraphQL tools:
            - GraphiQL
            - GraphQL Playground
            - Altair
            - GraphQL Voyager
        2. "Send to Repeater/Intruder" webhook endpoints (from GraphiQL & Co)
        3. `OPTIONS /handle-preflight` handler to bypass CORS policies

    Burp provides two APIs that could be used here:

        - ProxyRequestHandler
        - HttpHandler

    ProxyRequestHandler only gets executed on traffic coming from the Proxy tool
    (not Repeater, etc.), so we'd prefer using HttpHandler, but unfortunately
    that API is triggered after DNS resolution. As a result it doesn't work
    with virtual hostname https://inql.burp. So our only option is to use
    ProxyRequestHandler which is triggered before the DNS resolution, so we have
    an option to hijack these requests and redirect them to the embedded web server.

 */

class InternalHttpServer : ProxyRequestHandler {
    private val listeningPort: Int

    init {
        Burp.Montoya.proxy().registerRequestHandler(this)

        listeningPort = findAvailablePort()

        embeddedServer(Netty, port = listeningPort, host = "127.0.0.1") {

            routing {
                // Serve static files from /static/
                staticResources("/", "static")

                post("/send-to-repeater") {
                    val request = call.receiveText()
                    val httpRequest = graphqlRequestToHttpRequest(request)
                    Burp.Montoya.repeater().sendToRepeater(httpRequest)
                    call.response.status(HttpStatusCode.OK)
                }

                post("/send-to-intruder") {
                    val request = call.receiveText()
                    val httpRequest = graphqlRequestToHttpRequest(request)
                    Burp.Montoya.intruder().sendToIntruder(httpRequest)
                    call.response.status(HttpStatusCode.OK)
                }

                // OPTIONS handler for handling pre-flight requests
                options("/handle-preflight") {
                    val origin = call.request.header("Origin")
                    val allowedMethods = call.request.header("Access-Control-Request-Method") ?: "GET, PATCH, POST, OPTIONS"
                    val allowedHeaders = call.request.header("Access-Control-Request-Headers") ?: "Content-Type, InQL"
                    Logger.error("Handling Preflight Request for: Origin: $origin; Methods: $allowedMethods; Headers: $allowedHeaders")

                    // Check if the origin is whitelisted
                    if (isOriginWhitelisted(origin)) {
                        // Mirror the requested methods and headers
                        call.response.header("Access-Control-Allow-Origin", origin ?: "*")
                        call.response.header("Access-Control-Allow-Methods", allowedMethods)
                        call.response.header("Access-Control-Allow-Headers", allowedHeaders)
                        call.respond(HttpStatusCode.OK)
                    } else {
                        call.respond(HttpStatusCode.Forbidden)
                    }
                }
            }
        }.start()
    }

    // Converts a GraphQL request sent via 'Send to Repeater/Intruder' from GraphiQL to a Burp's HTTP request
    // An example body:
    //
    //   {
    //      "server": "https://graphql.anilist.co/graphql",
    //      "query": "query MyQuery {\n  Studio(id: 10) {\n    name\n  }\n}",
    //      "variables": {
    //         "test": 123,
    //         "other": {"one":"two"}
    //      },
    //      "headers": {
    //        "Authorization": "bearer JWT-onetwothree",
    //        "InQL":"anilist"
    //      }
    //   }
    //
    // variables and headers are optional (can be null, not present or {})
    private fun graphqlRequestToHttpRequest(request: String): HttpRequest {
        val json = Gson().fromJson(request, JsonObject::class.java)
        val server = json.get("server").asString
        val path = java.net.URI(server).path
        val query = json.get("query").asString
        val variables = json.get("variables").asJsonObject
        val headers = json.get("headers").asJsonObject

        // The body of HttpRequest is a JSON object with the following structure:
        //
        //   {
        //     "query": "query MyQuery {\n  Studio(id: 10) {\n    name\n  }\n}",
        //     "variables": {
        //       "test": 123,
        //       "other": {"one":"two"}
        //     }
        //   }
        val body = JsonObject()
        body.addProperty("query", query)
        if (variables != null) {
            body.add("variables", variables)
        }

        // Create HttpRequest object for Burp
        val service = HttpService.httpService(server)
        var httpRequest = HttpRequest.httpRequest()
            .withService(service)
            .withPath(path)
            .withMethod("POST")
            .withBody(Gson().toJson(body))

        // Add 'Host' header at the very least
        httpRequest = httpRequest.withAddedHeader("Host", service.host())

        // Go through headers coming from json (`headers` variable) and add them to the request
        for ((headerName, headerValue) in headers.entrySet()) {
            httpRequest = httpRequest.withAddedHeader(headerName, headerValue.asString)
        }

        // Add Content-Type json if not present
        if (!httpRequest.headers().any { it.name() == "Content-Type" }) {
            httpRequest = httpRequest.withAddedHeader("Content-Type", "application/json")
        }

        return httpRequest
    }

    private fun isOriginWhitelisted(origin: String?): Boolean {
        val whitelist = listOf("https://inql.burp") // Add other allowed origins as needed

        return origin in whitelist
    }

    private fun findAvailablePort(): Int {
        val random = Random()
        val minPort = 49152 // Random high port range
        val maxPort = 65535

        while (true) {
            val port = random.nextInt(maxPort - minPort) + minPort
            if (isPortAvailable(port)) {
                return port
            }
        }
    }

    private fun isPortAvailable(port: Int): Boolean {
        return try {
            ServerSocket(port).use { _ -> }
            true
        } catch (e: IOException) {
            false
        }
    }

    // Part of ProxyRequestHandler interface, executed first on every request coming through Burp's Proxy tool
    override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
        val request: HttpRequest

        // Request to https://inql.burp
        if (isInternalRequest(interceptedRequest)) {
            val service = HttpService.httpService("127.0.0.1", listeningPort, false)
            return ProxyRequestReceivedAction.continueWith(interceptedRequest.withService(service))
            //request = redirectToInternalWebServer(interceptedRequest)
            //return internalAction(request)
        }

        // Pre-flight request from GraphiQL or similar tool, auto-accept to bypass target's CORS policy
        if (isPreflightFromInternalTool(interceptedRequest)) {
            Logger.error("Pre-flight request from GraphiQL")
            request = redirectToPreflightHandler(interceptedRequest)
            return internalAction(request)
        }

        // Has our proprietary `InQL` header holding the session identifier
        // TODO: This is the place to add session headers, inject variables, etc
        if (hasInqlHeader(interceptedRequest)) {
            Logger.error("Request with InQL header")
            request = removeInqlHeader(interceptedRequest)
            return externalAction(request)
        }

        Logger.error("Unrelated request, letting through")
        return externalAction(interceptedRequest)
    }

    // Part of ProxyRequestHandler interface, leave it alone
    override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
    }

    private fun internalAction(request: HttpRequest): ProxyRequestReceivedAction {
        return ProxyRequestReceivedAction.doNotIntercept(request)
    }

    private fun externalAction(request: HttpRequest): ProxyRequestReceivedAction {
        return ProxyRequestReceivedAction.continueWith(request)
    }

    private fun isInternalRequest(request: HttpRequest): Boolean {
        return request.httpService().host() == "inql.burp"
    }

    private fun redirectToInternalWebServer(request: HttpRequest): HttpRequest {
        // Note that just doing:
        //
        //   val service = HttpService.httpService("127.0.0.1", listeningPort, false)
        //   return request.withService(service)
        //
        // is not enough because Burp messes up open connections, so the most robust way of changing
        // the service seems to be creating a brand-new request from scratch
        Logger.error("Redirecting to the internal web server")

        val service = HttpService.httpService("127.0.0.1", listeningPort, false)
        val path = request.path()
        val body = request.body()
        val method = request.method()
        val headers = request.headers()

        var newRequest = HttpRequest.httpRequest()
            .withService(service)
            .withBody(body)
            .withMethod(method)
            .withPath(path)

        for (header in headers) {
            newRequest = newRequest.withAddedHeader(header)
        }

        Logger.error("Redirect request created")
        return newRequest
    }

    private fun isPreflightFromInternalTool(request: HttpRequest): Boolean {
        return request.method() == "OPTIONS" &&
                request.headers().any { it.name() == "Access-Control-Request-Headers" && matchesInql(it.value()) }
    }

    // Check if "inql" is in the list of requested headers (within the comma-separated list Access-Control-Request-Headers)
    private fun matchesInql(requestedHeaders: String?): Boolean {
        return requestedHeaders?.split(',')?.any { it.trim().equals("inql", ignoreCase = true) } == true
    }

    private fun redirectToPreflightHandler(request: HttpRequest): HttpRequest {
        return redirectToInternalWebServer(request.withPath("/handle-preflight"))
    }

    private fun hasInqlHeader(request: HttpRequest): Boolean {
        return request.headers().any { it.name() == "InQL" }
    }

    private fun removeInqlHeader(request: HttpRequest): HttpRequest {
        return request.withRemovedHeader("InQL")
    }
}
