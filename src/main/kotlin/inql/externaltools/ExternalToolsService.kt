package inql.externaltools

import burp.Browser
import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.Config
import inql.InQL
import inql.Logger
import inql.ui.ErrorDialog
import inql.utils.get
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.util.*
import java.util.zip.GZIPOutputStream

class ExternalToolsService private constructor(){
    companion object {
        const val INTERNAL_INQL_HOST = "inql.burp"
        const val INTERNAL_INQL_ORIGIN = "https://$INTERNAL_INQL_HOST"
        const val INQL_HEADER = "X-Inql-Session"

        private var inql: InQL? = null
        private lateinit var instance: ExternalToolsService
        private val config = Config.getInstance()
        private val gson = Gson()

        enum class TOOL {
            TOOL_GRAPHIQL,
            TOOL_VOYAGER,
        }

        private val tool_paths = mapOf(
            TOOL.TOOL_GRAPHIQL to "graphiql",
            TOOL.TOOL_VOYAGER to "voyager",
        )

        fun init(inql: InQL) {
            this.inql = inql
        }
        fun startIfOff(): ExternalToolsService {
            if (this.inql == null) {
                Logger.error("Tried to start ExternalToolsService without initializing it first (inql instance is null)")
                throw Exception("Tried to start ExternalToolsService without initializing it first (inql instance is null)")
            }
            if (!this::instance.isInitialized) instance = ExternalToolsService()
            return instance
        }

        fun openURL(url: String) {
            Logger.info("Opening URL: $url")

            val useInternalBrowser = config.getBoolean("integrations.browser.internal")?: true
            Logger.info("Should use internal browser? $useInternalBrowser")

            if (useInternalBrowser) {
                if (Browser.launchEmbedded(url)) return
                // Burp's bundled Chromium may be missing (e.g. not downloaded, or installed
                // in a non-standard location), in which case the embedded launch fails. Fall
                // back to the external browser so the URL still opens instead of failing silently.
                Logger.warning("Embedded browser launch failed, falling back to external browser")
                if (!Browser.launchExternal(url)) {
                    ErrorDialog(
                        "InQL could not open the browser.\n\n" +
                            "Burp's embedded browser could not be found, and launching an external " +
                            "browser also failed. Install/download Burp's embedded browser " +
                            "(Settings → Suite → Embedded browser), or configure an external " +
                            "browser in InQL's settings.",
                    )
                }
            } else {
                if (!Browser.launchExternal(url)) {
                    ErrorDialog(
                        "InQL could not open the external browser.\n\n" +
                            "Configure an external browser command in InQL's settings, or enable " +
                            "Burp's embedded browser.",
                    )
                }
            }
        }

        private fun encodeRequestData(request: HttpRequest): String? {
            // val url = request.url()
            // val profileName = request.headers().get(this.INQL_HEADER) ?: ""
            val body: JsonObject
            val query: String
            var variables: JsonObject = JsonObject()

            try {
                body = gson.fromJson(request.bodyToString(), JsonObject::class.java)
                query = body.get("query").asString
                val tmpVariables = body.get("variables")
                if (tmpVariables != null && tmpVariables.isJsonObject){
                    variables = body.get("variables").asJsonObject
                }
            } catch (e: Exception) {
                Logger.error("Error deserializing request's body to JSON")
                e.message?.let { Logger.error(it) }
                return null
            }

            // Create JSON object to send to IDE
            val objectToSend = JsonObject()
            // objectToSend.addProperty("url", url)
            // objectToSend.addProperty("session", profileName)
            objectToSend.addProperty("query", query)
            objectToSend.add("variables", variables)

            // Stringify
            val jsonObject = gson.toJson(objectToSend)

            // Compress
            val outputStream = ByteArrayOutputStream()
            val gzipStream = GZIPOutputStream(outputStream)
            gzipStream.write(jsonObject.toByteArray())
            gzipStream.close()

            // Base64 encode
            val base64Encoded = Base64.getUrlEncoder().encodeToString(outputStream.toByteArray())
            return base64Encoded
        }

        fun sendRequestToEmbeddedTool(request: HttpRequest?, tool: TOOL) {
            if (request == null) {
                Logger.debug("Null request, aborting")
                return
            }

            // Ensure ExternalToolsService is running
            this.startIfOff()

            val targetParam = "target=${URLEncoder.encode(request.url(), "UTF-8")}"
            val session = request.headers().get(this.INQL_HEADER) ?: ""
            val sessionParam = if (session.isBlank()) "" else "&session=${URLEncoder.encode(session, "UTF-8")}"
            val base64Encoded = encodeRequestData(request)
            if (base64Encoded == null) {
                Logger.error("Error while encoding request data, aborting...")
                return
            }

            openURL("${INTERNAL_INQL_ORIGIN}/${this.tool_paths[tool]}?$targetParam$sessionParam#data:$base64Encoded")
        }
    }

    val webserver: WebServer
    val interceptor: ExternalToolsRequestFixer

    init {
        this.webserver = WebServer()
        this.interceptor = ExternalToolsRequestFixer(inql!!, this.webserver.listeningPort)
        Logger.info("Registering external tools interceptor")
        Burp.Montoya.proxy().registerRequestHandler(this.interceptor)
        Burp.Montoya.proxy().registerResponseHandler(this.interceptor)
        Logger.info("Started external tools service")
    }
}