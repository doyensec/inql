package inql.externaltools

import burp.Burp
import inql.InQL
import inql.Logger

class ExternalToolsService private constructor(){
    companion object {
        private var inql: InQL? = null
        private lateinit var instance: ExternalToolsService

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
    }

    public val webserver: WebServer
    public val interceptor: ExternalToolsRequestFixer

    init {
        this.webserver = WebServer()
        this.interceptor = ExternalToolsRequestFixer(inql!!, this.webserver.listeningPort)
        Logger.info("Registering external tools interceptor")
        Burp.Montoya.proxy().registerRequestHandler(this.interceptor)
        Burp.Montoya.proxy().registerResponseHandler(this.interceptor)
        Logger.info("Started external tools service")
    }
}