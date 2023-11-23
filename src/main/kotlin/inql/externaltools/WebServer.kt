package inql.externaltools

import burp.Burp
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.Logger
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.netty.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import java.io.IOException
import java.net.ServerSocket
import java.util.*

/*
    This file defines embedded HTTP server with the following functionality:

        1. Serving web based GraphQL tools:
            - GraphiQL
            - GraphQL Playground
            - Altair
            - GraphQL Voyager
        2. "Send to Repeater/Intruder" webhook endpoints (from GraphiQL & Co)

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

class WebServer {
    public val listeningPort: Int
    public val server: NettyApplicationEngine

    init {
        this.listeningPort = findAvailablePort()
        this.server = embeddedServer(Netty, port = listeningPort, host = "127.0.0.1", module = {
            routing {
                // Serve static files from /static/
                staticResources("/", "static")

                post("/send-to-repeater") {
                    val request = call.receiveText()
                    try {
                        val httpRequest = WebServer.deserializeRequest(request)
                        Burp.Montoya.repeater().sendToRepeater(httpRequest)
                        call.response.status(HttpStatusCode.OK)
                    } catch (e: Exception) {
                        Logger.error("Error handling /send-to-repeater request from external service")
                        Logger.error(e.message ?: "No Exception message provided")
                        call.response.status(HttpStatusCode.BadRequest)
                        return@post
                    }
                }

                post("/send-to-intruder") {
                    val request = call.receiveText()
                    try {
                        val httpRequest = WebServer.deserializeRequest(request)
                        Burp.Montoya.intruder().sendToIntruder(httpRequest)
                        call.response.status(HttpStatusCode.OK)
                    } catch (e: Exception) {
                        Logger.error("Error handling /send-to-intruder request from external service")
                        Logger.error(e.message ?: "No Exception message provided")
                        call.response.status(HttpStatusCode.BadRequest)
                        return@post
                    }
                }

                // For CORS and Introspection request replacing
                post("/dummy") {
                    call.response.status(HttpStatusCode.OK)
                }

                options("/dummy") {
                    call.response.status(HttpStatusCode.OK)
                }
            }
        }).start()
        Logger.debug("Successfully started embedded web server on port $listeningPort")
    }

    companion object {
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
        fun deserializeRequest(request: String): HttpRequest {
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
            if (!httpRequest.headers().any { it.name().lowercase() == "content-type" }) {
                httpRequest = httpRequest.withAddedHeader("Content-Type", "application/json")
            }

            return httpRequest
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
    }
}