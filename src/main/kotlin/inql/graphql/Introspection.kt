package inql.graphql

import burp.Burp
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import inql.Logger
import inql.utils.withUpsertedHeader

class Introspection {
    companion object {
        /** Exact JSON body for Apollo Federation `_service { sdl }` (see PLAN: schema discovery fallback). */
        private const val FEDERATION_SDL_REQUEST_BODY = """{"query":"query{_service{sdl}}","operationName":null}"""

        /**
         * POST the same [request] URL/headers with Federation SDL query; returns raw SDL or null.
         */
        fun sendFederationSdlQuery(request: HttpRequest): String? {
            Logger.debug("Federation SDL fallback query to '${request.url()}'.")
            val response = try {
                Burp.Montoya.http().sendRequest(request.withBody(FEDERATION_SDL_REQUEST_BODY)).response()
            } catch (e: Exception) {
                Logger.info("Federation SDL request failed: ${e.message}")
                return null
            }

            if (response.statusCode() >= 400) {
                Logger.info("Federation SDL query failed, status: ${response.statusCode()}")
                return null
            }

            val raw = response.bodyToString()
            Logger.debug("Federation SDL response: $raw")

            val gson = Gson()
            val root: Map<*, *>
            try {
                root = gson.fromJson(raw, Map::class.java) ?: return null
            } catch (e: Exception) {
                Logger.info("Could not parse Federation SDL response as JSON: ${e.message}")
                return null
            }

            if (root.containsKey("errors")) {
                Logger.info("Federation SDL response contained errors")
                (root["errors"] as? Collection<*>)?.forEach { Logger.info("Error: $it") }
                return null
            }

            val data = root["data"] as? Map<*, *> ?: run {
                Logger.info("Federation SDL response missing data")
                return null
            }
            val service = data["_service"] as? Map<*, *> ?: run {
                Logger.info("Federation SDL response missing data._service")
                return null
            }
            val sdl = service["sdl"]
            if (sdl == null) {
                Logger.info("Federation SDL: data._service.sdl is null or absent")
                return null
            }
            if (sdl !is String) {
                Logger.info("Federation SDL: unexpected type for sdl")
                return null
            }
            if (sdl.isBlank()) {
                Logger.info("Federation SDL: empty SDL string")
                return null
            }
            return sdl
        }

        fun sendIntrospectionQuery(url: String, headers: Map<String, String>): String? {
            // val request = IntrospectionHttpRequest(method = "POST", url, headers)
            var request = HttpRequest.httpRequest()
                .withService(HttpService.httpService(url))
                .withMethod("POST")
                .withUpsertedHeader("Content-Type", "application/json")
            headers.forEach { request = request.withUpsertedHeader(it.key, it.value) }
            return this.sendIntrospectionQuery(request)
        }

        fun sendIntrospectionQuery(request: HttpRequest): String? {
            for (version in IntrospectionQuery.Version.entries.asReversed()) {
                return sendIntrospectionQueryVersion(request, version) ?: continue
            }
            Logger.warning("Introspection seems disabled for this endpoint: ${request.url()}")
            return null
        }

        fun sendIntrospectionQueryVersion(request: HttpRequest, version: IntrospectionQuery.Version): String? {
            val gson = Gson()
            Logger.debug("Introspection query about to be sent with version '$version' to '${request.url()}'.")
            val body = gson.toJson(mapOf("query" to IntrospectionQuery.get(version)))
            Logger.debug("Acquired introspection query body")
            // TODO: Think of a way to handle exception for the following LoC.
            //  It can throw an UnknownHostException inside internal Burp thread and cannot be caught before it unwraps
            //  on error logs
            val response = Burp.Montoya.http().sendRequest(request.withBody(body)).response()
            Logger.debug("Sent the request and got the response")

            if (response.statusCode() >= 400) {
                Logger.info("Could not query schema from $request.url (version: $version), status code: ${response.statusCode()}")
                return null
            }

            val rawResponse = response.bodyToString()
            Logger.debug("Received response: $rawResponse")

            
            val schema: Map<*, *>
            try {
                schema = gson.fromJson(rawResponse, Map::class.java)
                Logger.debug("JSON parsed successfully")
            } catch (e: Exception) {
                Logger.info("Could not parse introspection response")
                Logger.info("Exception: $e")
                throw e
            }

            if (schema.containsKey("errors")) {
                Logger.info("Received errors from ${request.url()} (version $version):")
                (schema["errors"] as Collection<*>).forEach { Logger.info("Error: $it") }
                return null
            }

            Logger.info("Found the introspection response with $version version schema.")
            Logger.debug("Received introspection schema: $rawResponse")

            return rawResponse
        }
    }
}
