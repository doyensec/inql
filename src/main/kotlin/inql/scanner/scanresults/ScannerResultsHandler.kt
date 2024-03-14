package inql.scanner.scanresults

import burp.api.montoya.http.message.requests.HttpRequest
import inql.Config
import inql.Logger
import inql.graphql.formatting.Formatter
import inql.ui.SendFromInqlHandler
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

class ScannerResultsHandler(val view: ScanResultsView):
    SendFromInqlHandler(view.scannerTab.inql, false) {
    private val config = Config.getInstance()
    private val stripCommentsFormatter = Formatter(minimized = false, spaces = 4, stripComments = true, asHTML = false, isIntrospection = true)

    override fun getText(): String = view.payloadView.getText()

    private fun stripGraphQLComments(query: String): String =
        if (config.getBoolean("editor.send_to.strip_comments"))
            stripCommentsFormatter.format(query) else query

    override fun getRequest(): HttpRequest? =
        view.selectedNode?.let { node ->
            val content = runBlocking { node.getContent() }
            when (content) {
                is ScanResult.GraphQL -> {
                    val strippedQuery = stripGraphQLComments(content.content)
                    Logger.error("Request: ${view.session?.requestTemplate}")

                    val reqData = buildJsonObject {
                        put("variables", buildJsonObject {})
                        put("query", strippedQuery)
                    }

                    return view.session?.requestTemplate?.withBody(reqData.toString())
                }
                else -> return null
            }
        }
}