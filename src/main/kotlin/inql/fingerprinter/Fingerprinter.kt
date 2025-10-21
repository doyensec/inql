package inql.fingerprinter

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONObject
import inql.InQL
import inql.Logger
import inql.ui.BorderPanel
import inql.utils.MarkdownToHtmlConverter
import kotlinx.coroutines.*
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Desktop
import java.awt.Font
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URI
import javax.swing.*
import javax.swing.event.HyperlinkEvent

class Fingerprinter(private val inql: InQL) : BorderPanel(), ActionListener {

    private val coroutineScope = CoroutineScope(Dispatchers.IO)
    private var fingerPrinterJob: Job? = null
    private val markdownEditorPane = JEditorPane()
    private val urlField = JTextField()
    private val sendButton = JButton("Start fingerprinting").also {
        it.addActionListener(this)
        it.background = Color(255, 88, 18)
        it.foreground = Color.WHITE
        it.font = it.font.deriveFont(Font.BOLD)
        it.isBorderPainted = false
    }
    fun focus() = inql.focusTab(this)
    var url: String
        get() = this.urlField.text
        set(s) {
            this.urlField.text = s
        }
    var request: HttpRequest
        get() = this.requestEditor.request
        set(r) {
            this.requestEditor.request = r
        }
    private val requestEditor = Burp.Montoya.userInterface().createHttpRequestEditor()

    fun loadFromRequest(req: HttpRequest) {
        this.url = req.url()
        this.request = req
        this.focus()
        this.urlField.requestFocus()
    }

    init {
        // Request editor section
        val urlFieldPanel = BorderPanel().also {
            it.add(JLabel("Target: "), BorderLayout.WEST)
            it.add(this.urlField, BorderLayout.CENTER)
            it.add(sendButton, BorderLayout.EAST)
        }
        val reqEditorPanel = BorderPanel().also {
            it.add(urlFieldPanel, BorderLayout.NORTH)
            it.add(this.requestEditor.uiComponent(), BorderLayout.CENTER)
        }

        val editorPane = JEditorPane()
        editorPane.setContentType("text/html")
        editorPane.setText("""
<h2>Engine Fingerprinter</h2>
This tab allows fingerprinting engine used by the GraphQL server. It works by sending various types of requests, including malformed ones, and comparing the responses with those typically returned by known engines. 
<br/>
When a match is found, it displays the server’s security features based on data from the GraphQL Threat Matrix.
<br/><br/>
This feature is inspired by the graphw00f CLI tool.
<br/>
<h2>References</h2>
- https://github.com/dolevf/graphw00f<br/>
- https://github.com/nicholasaleks/graphql-threat-matrix<br/>
""")
        editorPane.setEditable(false)

        // Left section
        val leftSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(editorPane),
            reqEditorPanel,
        )

        markdownEditorPane.setContentType("text/html")
        markdownEditorPane.setText("""
<h2>Engine Fingerprinter</h2>
The results will appear here
""")
        markdownEditorPane.setEditable(false)
        markdownEditorPane.addHyperlinkListener { e ->
            if (e.eventType == HyperlinkEvent.EventType.ACTIVATED) {
                try {
                    Desktop.getDesktop().browse(URI(e.url.toString()))
                } catch (ex: Exception) {
                    println("Failed to open link: ${ex.message}")
                }
            }
        }

        // Right section
        val rightSection = JScrollPane(
            markdownEditorPane,
        )
        rightSection.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        rightSection.verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED



        // Main layout
        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSection,
        )
        horizontalSplit.resizeWeight = 0.4
        Burp.Montoya.userInterface().applyThemeToComponent(horizontalSplit)
        this.add(horizontalSplit)
    }

    private fun setMarkdown(markdown: String ) {
        val html = MarkdownToHtmlConverter.renderMarkdownToHtml(markdown)

        val htmlContent = """
    <html>
      <head>
        <style>
          ul { margin-left: 20px; }
          table { border-collapse: collapse; width: 100%; margin: 16px 0; font-family: Arial, sans-serif; }
          th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
        </style>
      </head>
      <body>
        $html
      </body>
    </html>
""".trimIndent()

        markdownEditorPane.setText(htmlContent)
        markdownEditorPane.setCaretPosition(0) // Scroll to top
    }

    private fun setMarkdownFromUrl(enginedetails: Helpers.Companion.EngineDetails) {
        val markdown = try {
            MarkdownToHtmlConverter.downloadMarkdown(enginedetails.ref)
        } catch (e: Exception) {
            "**Name**: ${enginedetails.name}<br/>"+
            "**Url**: [${enginedetails.url}](${enginedetails.url})<br/>" +
            "**Matrix Reference**: [${enginedetails.ref}](${enginedetails.ref})<br/>" +
            "**Technologies**: ${enginedetails.technology.toString()}<br/><br />" +
            "Unable to retrieve GraphQL Threat Matrix data for this engine. The issue is likely external and not caused by InQL."
        }

        setMarkdown("# Server Engine Found: ${enginedetails.name}\n$markdown")
    }

    override fun actionPerformed(e: ActionEvent?) {
        Logger.debug("Initiate Attack handler fired")
        setMarkdownInprogress()
        fingerPrinterJob = coroutineScope.launch {
            try {
                run()
            } finally {
            }
        }
    }

    fun cancel() {
        fingerPrinterJob?.cancel()
    }

    private fun setMarkdownInprogress() {
        markdownEditorPane.setText("""
<h2>Engine Fingerprinter</h2>
Fingerprinting...
""")
    }

    private suspend fun run() {
        if (check()) {
            val engine = execute()
            Logger.debug(engine.toString())
            if (engine != null) {
                Helpers.engines[engine]?.let { setMarkdownFromUrl(it) }
            } else {
                setMarkdown("# Couldn't fingerprint server engine")
            }
        }
    }

    fun check(): Boolean {
        val query = """
            query { __typename }
        """.trimIndent()
        val response = graphQuery(query)
        when {

            response.optJSONObject("data") != null -> {
                val typename = response.optJSONObject("data")?.optString("__typename")
                if (typename in listOf("Query", "QueryRoot", "query_root")) return true
                return true
            }
            response.has("errors") -> return true
            else -> return false
        }
    }

    private suspend fun execute(): String? {
        return when {
            engineInigo() -> "inigo"
            engineLighthouse() -> "lighthouse"
            engineCaliban() -> "caliban"
            engineLacinia() -> "lacinia"
//            engineJaal() -> "jaal" // TODO
            engineMorpheus() -> "morpheus-graphql"
            engineMercurius() -> "mercurius"
            engineGraphqlYoga() -> "graphql_yoga"
            engineAgoo() -> "agoo"
            engineTailcall() -> "tailcall"
            engineDgraph() -> "dgraph"
            engineGraphene() -> "graphene"
            engineAriadne() -> "ariadne"
            engineApollo() -> "apollo"
            engineAwsAppSync() -> "aws-appsync"
            engineHasura() -> "hasura"
            engineWpGraphql() -> "wpgraphql"
            engineGraphqlJava() -> "graphql-java"
            engineHypergraphql() -> "hypergraphql"
            engineRuby() -> "ruby-graphql"
            engineGraphqlPhp() -> "graphql-php"
            engineGqlGen() -> "gqlgen"
            engineGraphqlGo() -> "graphql-go"
            engineJuniper() -> "juniper"
            engineSangria() -> "sangria"
            engineDianaJl() -> "dianajl"
            engineStrawberry() -> "strawberry"
            engineTartiflette() -> "tartiflette"
            engineDirectus() -> "directus"
            engineAbsinthe() -> "absinthe-graphql"
            engineGraphqlDotNet() -> "graphql-dotnet"
            enginePgGraphql() -> "pg_graphql"
            engineHotChocolate() -> "hotchocolate"
            engineBallerina() -> "ballerina"
            engineFlutter() -> "flutter"
            else -> null
        }
    }

    private fun graphQuery(query: String): JSONObject {
        try {
            val newQuery = JsonObject()
            newQuery.addProperty("query", query)
            val newBody = Gson().toJson(newQuery)
            val req =
                this.request.withService(burp.api.montoya.http.HttpService.httpService(this.url)).withBody(newBody)
            val response = Burp.Montoya.http().sendRequest(req)
            val resp = response.response()

            return JSONObject(resp.body().toString())
        } catch (e: Exception) {
            return JSONObject()
        }
    }

    private fun errorContains(resp: JSONObject, msg: String): Boolean {
        if (resp.optJSONArray("errors") != null) {
            return resp.optJSONArray("errors")?.let { errors ->
                for (i in 0 until errors.length()) {
                    if (errors.getJSONObject(i).toString().contains(msg)) return true
                }
                return false
            } ?: false
        } else if (resp.optString("error") != null) {
            return resp.toString().contains(msg)
        }

        return false
    }

    private suspend fun engineGraphqlYoga(): Boolean {
      Logger.debug("engineGraphqlYoga")
        val query = """
      subscription {
         __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "asyncExecutionResult[Symbol.asyncIterator] is not a function") || errorContains(resp, "Unexpected error.")
    }

    private suspend fun engineApollo(): Boolean {
      Logger.debug("engineApollo")
        var query = """
      query @skip {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Directive \\\"@skip\\\" argument \\\"if\\\" of type \\\"Boolean!\\\" is required, but it was not provided.")) {
            return true
        }

        query = """
      query @deprecated {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Directive \\\"@deprecated\\\" may not be used on QUERY.")
    }
    private suspend fun engineAwsAppSync(): Boolean {
      Logger.debug("engineAwsAppSync")
        val query = "query @skip { __typename }".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "MisplacedDirective")
    }
    private suspend fun engineGraphene(): Boolean {
      Logger.debug("engineGraphene")
        val query = """aaa""".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Syntax Error GraphQL (1:1)")
    }
    private suspend fun engineHasura(): Boolean {
      Logger.debug("engineHasura")
        var query = """
      query @cached {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)

        if (resp.optJSONObject("data")?.optString("__typename") == "query_root") {
            return true
        }
        query = """
     query {
       aaa
      }
    """
        resp = graphQuery(query)
        if (errorContains(resp, "field \"aaa\" not found in type: 'query_root'")) {
            return true
        }

        query = """
      query @skip {
        __typename
      }
    """
        resp = graphQuery(query)
        if (errorContains(resp, "directive \"skip\" is not allowed on a query")) {
            return true
        }

        query = """
      query {
        __schema
      }
    """
        resp = graphQuery(query)

        return errorContains(resp, "missing selection set for \"__Schema\"")
    }

    private suspend fun engineGraphqlPhp(): Boolean {
      Logger.debug("engineGraphqlPhp")
        var query = """
      query ! {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Syntax Error: Cannot parse the unexpected character \\\"?\\\".")) {
            return true
        }

        query = """
      query @deprecated {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Directive \\\"deprecated\\\" may not be used on \\\"QUERY\\\".")
    }

    private suspend fun engineRuby(): Boolean {
      Logger.debug("engineRuby")
        var query = """
     query @skip {
       __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")) {
            return true
        } else if (errorContains(resp, "Directive \'skip\' is missing required arguments: if")) {
            return true
        }

        query = """
     query @deprecated {
       __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "'@deprecated' can't be applied to queries")) {
            return true
        }
        query = """
      query {
       __typename {
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Parse error on \\\"}\\\" (RCURLY)")) {
            return true
        }
        query = """
      query {
        __typename @skip
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Directive 'skip' is missing required arguments: if")
    }

    private suspend fun engineHypergraphql(): Boolean {
      Logger.debug("engineHypergraphql")
        var query = """
     zzz {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Validation error of type InvalidSyntax: Invalid query syntax.")) {
            return true
        }
        query = """
      query {
        alias1:__typename @deprecated
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'")
    }

    private suspend fun engineGraphqlJava(): Boolean {
      Logger.debug("engineGraphqlJava")
        var query = """
     queryy  {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Invalid Syntax : offending token 'queryy'")) {
            return true
        }
        query = """
     query @aaa@aaa {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Validation error of type DuplicateDirectiveName: Directives must be uniquely named within a location.")) {
            return true
        }
        query = ""
        resp = graphQuery(query)
        return errorContains(resp, "Invalid Syntax : offending token '<EOF>'")
    }

    private suspend fun engineAriadne(): Boolean {
      Logger.debug("engineAriadne")
        var query = """
      query {
        __typename @abc
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Unknown directive '@abc'.") && resp.optJSONObject("data") != null){
            return true
        }

        query = ""
        resp = graphQuery(query)
        return errorContains(resp, "The query must be a string.")
    }

    private suspend fun engineWpGraphql(): Boolean {
      Logger.debug("engineWpGraphql")
        var query = ""
        var resp = graphQuery(query)
        if (errorContains(resp, "GraphQL Request must include at least one of those two parameters: \\\"query\\\" or \\\"queryId\\\"")) {
            return true
        }

        query = """
     query {
       alias1$1:__typename
     }
    """.trimIndent()
        resp = graphQuery(query)
        if (!errorContains(resp, "Syntax Error: Expected Name, found $")){
            return false
        }

        val ext = resp.optJSONObject("extensions") ?: return false
        val dbg = ext.optJSONArray("debug") ?: return false

        val debugMsg = JSONObject(dbg.get(0))
        val dbgMsgType = debugMsg.optString("type")
        val dbgMsgMessage = debugMsg.optString("message")

        return (dbgMsgType == "DEBUG_LOGS_INACTIVE" || dbgMsgMessage == "GraphQL Debug logging is not active. To see debug logs, GRAPHQL_DEBUG must be enabled.")
    }

    private suspend fun engineGqlGen(): Boolean {
      Logger.debug("engineGqlGen")
        var query = """
      query  {
      __typename {
    }
    """.trimIndent()
        var resp = graphQuery(query)

        if (errorContains(resp, "expected at least one definition")) {
            return true
        }
        query = """
      query  {
      alias^_:__typename {
    }
    """.trimIndent()
        resp = graphQuery(query)

        return errorContains(resp, "Expected Name, found <Invalid>")
    }
    private suspend fun engineGraphqlGo(): Boolean {
      Logger.debug("engineGraphqlGo")
        var query = """
      query {
      __typename {
      }
    """.trimIndent()
        var resp = graphQuery(query)

        if (errorContains(resp, "Unexpected empty IN")) {
            return true
        }

        query = ""
        resp = graphQuery(query)

        if (errorContains(resp, "Must provide an operation.")) {
            return true
        }

        query = """
      query {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        val typename = resp.optJSONObject("data")?.optString("__typename")
        return typename == "RootQuery"
    }

    private suspend fun engineJuniper(): Boolean {
      Logger.debug("engineJuniper")
        var query = """
      queryy {
        __typename
    }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Unexpected \"queryy\"")) {
            return true
        }

        query = ""
        resp = graphQuery(query)

        return errorContains(resp, "Unexpected end of input")
    }
    private suspend fun engineSangria(): Boolean {
      Logger.debug("engineSangria")
        val query = """
      queryy {
        __typename
    }
    """.trimIndent()
        val resp = graphQuery(query)
        val syntaxError = resp.optString("syntaxError")
        val msg = "Syntax error while parsing GraphQL query. Invalid input \"queryy\", expected ExecutableDefinition or TypeSystemDefinition"
        return syntaxError.contains(msg)
    }

    private suspend fun engineFlutter(): Boolean {
      Logger.debug("engineFlutter")
        val query = """
      query {
        __typename @deprecated
    }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Directive \"deprecated\" may not be used on FIELD.")
    }

    private suspend fun engineDianaJl(): Boolean {
      Logger.debug("engineDianaJl")
        val query = """queryy { __typename }""".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \"queryy\"") || errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \\\"queryy\\\"")
    }

    private suspend fun engineStrawberry(): Boolean {
      Logger.debug("engineStrawberry")
        val query = """
      query @deprecated {
        __typename
      }""".trimIndent()
        val resp = graphQuery(query)
        return (errorContains(resp, "Directive '@deprecated' may not be used on query.")  && resp.keySet().contains("data"))
    }

    private suspend fun engineTartiflette(): Boolean {
      Logger.debug("engineTartiflette")
        var query = """
      query @a { __typename }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Unknow Directive < @a >.")) {
            return true
        }

        query = """
      query @skip { __typename }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Missing mandatory argument < if > in directive < @skip >.")) {
            return true
        }

        query = """
      query { graphwoof }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Field graphwoof doesn't exist on Query")) {
            return true
        }

        query = """
      query {
        __typename @deprecated
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Directive < @deprecated > is not used in a valid location.")) {
            return true
        }

        query = """
      queryy {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "syntax error, unexpected IDENTIFIER")
    }

    private suspend fun engineTailcall(): Boolean {
      Logger.debug("engineTailcall")
        val query = """
      aa {
        __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)

        return errorContains(resp, "expected executable_definition")
    }

    private suspend fun engineDgraph(): Boolean {
      Logger.debug("engineDgraph")
        var query = """
      query {
        __typename @cascade
      }
    """.trimIndent()
        var resp = graphQuery(query)
        val typename = resp.optJSONObject("data")?.optString("__typename")
        if (typename == "Query") {
            return true
        }

        query = """
      query {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)

        return errorContains(resp, "Not resolving __typename. There's no GraphQL schema in Dgraph. Use the /admin API to add a GraphQL schema")
    }

    private suspend fun engineDirectus(): Boolean {
      Logger.debug("engineDirectus")
        val query = ""

        val resp = graphQuery(query)
        val errors = resp.optJSONArray("errors")
        return (JSONObject(errors.get(0)).optJSONObject("extensions")?.optString("code") == "INVALID_PAYLOAD")
    }

    private suspend fun engineLighthouse(): Boolean {
      Logger.debug("engineLighthouse")
        val query = """
      query {
        __typename @include(if: falsee)
      }
    """.trimIndent()
        val resp = graphQuery(query)
        if (errorContains(resp, "Internal server error")) { // TODO or errorContains(resp, 'internal', part='category')):
            return true
        }

        return false
    }

    private suspend fun engineAgoo(): Boolean {
      Logger.debug("engineAgoo")
        val query = """
      query {
        zzz
      }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "eval error")
    }
    private suspend fun engineMercurius(): Boolean {
      Logger.debug("engineMercurius")
        val query = ""
        val resp = graphQuery(query)

        return errorContains(resp, "Unknown query") || errorContains(resp, "MER_ERR_GQL_VALIDATION")
    }
    private suspend fun engineMorpheus(): Boolean {
      Logger.debug("engineMorpheus")
        val query = """
      queryy {
          __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)

        return (errorContains(resp, "expecting white space") || errorContains(resp, "offset"))
    }
    private suspend fun engineLacinia(): Boolean {
      Logger.debug("engineLacinia")
        val query = """
      query {
        inql
      }
    """.trimIndent()

        val resp = graphQuery(query)

        return errorContains(resp, "Cannot query field `inql' on type `QueryRoot'.")
    }

    // TODO
//    private suspend fun engineJaal(): Boolean {
//        var query = """{}""".trimIndent()
//        var resp = self.graph_query(self.url, payload=query, operation='{}')
//
//    if errorContains(resp, 'must have a single query') or errorContains(resp, 'offset'):
//      return true
//
//    return false
//    }

  private suspend fun engineCaliban(): Boolean {
    Logger.debug("engineCaliban")
    val query = """
        query {
            __typename
        }

        fragment woof on __Schema {
            directives {
                name
            }
        }
        """.trimIndent()

    val resp = graphQuery(query)

    return errorContains(resp, "Fragment 'woof' is not used in any spread")
}

  private suspend fun engineAbsinthe(): Boolean {
    Logger.debug("engineAbsinthe")
    val query = """
        query {
            inql
        }
        """.trimIndent()

    val resp = graphQuery(query)

    return errorContains(resp, "Cannot query field \\\"inql\\\" on type \\\"RootQueryType\\\".")
}
  private suspend fun engineGraphqlDotNet(): Boolean {
    Logger.debug("engineGraphqlDotNet")
    val query = "query @skip { __typename }".trimIndent()
    val resp = graphQuery(query)
    return errorContains(resp, "Directive 'skip' may not be used on Query.")
  }

  private suspend fun enginePgGraphql(): Boolean {
    Logger.debug("enginePgGraphql")
    val query = """query { __typename @skip(aa:true) }""".trimIndent()
    val resp = graphQuery(query)
    return errorContains(resp, "Unknown argument to @skip: aa")
  }

  private suspend fun engineHotChocolate(): Boolean {
    Logger.debug("engineHotChocolate")
    var query = """
        queryy  {
            __typename
        }
        """.trimIndent()
    var resp = graphQuery(query)
    if (errorContains(resp, "Unexpected token: Name.")) {
        return true
    }

    query = """
        query @aaa@aaa {
            __typename
        }
        """.trimIndent()
    resp = graphQuery(query)
    return errorContains(resp, "The specified directive `aaa` is not supported by the current schema.")
  }

  private suspend fun engineInigo(): Boolean {
    Logger.debug("engineInigo")
      val query = """
        query  {
            __typename
        }
        """.trimIndent()
      val resp = graphQuery(query)
      return resp.optJSONObject("extensions") != null && resp.optJSONObject("extensions").keySet().contains("inigo")
  }

  private suspend fun engineBallerina(): Boolean {
    Logger.debug("engineBallerina")
    val query = """
        query {
            __typename
            ...A
        }

        fragment A on Query {
            ...B
        }

        fragment B on Query {
            ...A
        }
        """.trimIndent()
    
    val resp = graphQuery(query)
    return errorContains(resp, "Cannot spread fragment \"A\" within itself via \"B\"")
    }

}