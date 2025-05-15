package inql.fingerprinter

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONObject
import inql.InQL
import inql.Logger
import inql.attacker.Attack
import inql.ui.BorderPanel
import inql.utils.MarkdownToHtmlConverter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
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
TODO
""")
        editorPane.setEditable(false)

        // Left section
        val leftSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(editorPane),
            reqEditorPanel,
        )

        Burp.Montoya.userInterface().applyThemeToComponent(leftSection)

        markdownEditorPane.setContentType("text/html")
        markdownEditorPane.setText("""
<h2>Engine Fingerprinter</h2>
TODO
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
        rightSection.verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS
        rightSection.horizontalScrollBar.unitIncrement = 16
        rightSection.verticalScrollBar.unitIncrement = 16

        // Main layout
        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSection,
        )
        horizontalSplit.resizeWeight = 0.4
        this.add(horizontalSplit)

//        setMarkdownFromUrl("https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphene.md")
    }

    private fun setMarkdown(markdown: String ) {
        val html = MarkdownToHtmlConverter.renderMarkdownToHtml(markdown)

        val htmlContent = """
    <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; padding: 12px; background-color: #f4f4f4; }
          h1, h2, h3 { color: #333; }
          code { background: #eee; padding: 2px 4px; border-radius: 4px; font-family: monospace; }
          pre { background: #eee; padding: 8px; border-radius: 4px; overflow-x: auto; }
          a { color: #1a0dab; text-decoration: none; }
          a:hover { text-decoration: underline; }
          ul { margin-left: 20px; }
          table { border-collapse: collapse; width: 100%; margin: 16px 0; font-family: Arial, sans-serif; }
          th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
          th { background-color: #f0f0f0; }
          tr:nth-child(even) { background-color: #fafafa; }
          tr:hover { background-color: #f1f1f1; }
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

    private fun setMarkdownFromUrl(url: String) {
        val markdown = try {
            MarkdownToHtmlConverter.downloadMarkdown(url)
        } catch (e: Exception) {
            "Error when fetching information"
        }

        setMarkdown("# Server Engine Found:\n$markdown")
    }

    override fun actionPerformed(e: ActionEvent?) {
        Logger.debug("Initiate Attack handler fired")
        this.coroutineScope.launch { run() }
    }

    private fun run() {
        if (check()) {
            val engine = execute()
            Logger.debug(engine.toString())
            if (engine != null) {
                Helpers.engines[engine]?.let { setMarkdownFromUrl(it.ref) }
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

    private fun execute(): String? {
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
            engineGraphqlApiForWp() -> "graphql-api-for-wp"
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
        return resp.optJSONArray("errors")?.let { errors ->
            for (i in 0 until errors.length()) {
                if (errors.getJSONObject(i).toString().contains(msg)) return true
            }
            return false
        } ?: false
    }

    private fun engineGraphqlYoga(): Boolean {
        val query = """
      subscription {
         __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "asyncExecutionResult[Symbol.asyncIterator] is not a function") || errorContains(resp, "Unexpected error.")
    }

    private fun engineApollo(): Boolean {
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
    private fun engineAwsAppSync(): Boolean {
        val query = "query @skip { __typename }".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "MisplacedDirective")
    }
    private fun engineGraphene(): Boolean {
        val query = """aaa""".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Syntax Error GraphQL (1:1)")
    }
    private fun engineHasura(): Boolean {
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

    private fun engineGraphqlPhp(): Boolean {
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

    private fun engineRuby(): Boolean {
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

    private fun engineHypergraphql(): Boolean {
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

    private fun engineGraphqlJava(): Boolean {
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

    private fun engineAriadne(): Boolean {
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

    private fun engineGraphqlApiForWp(): Boolean {
        var query = """
     query {
       alias1$1:__typename
     }
    """.trimIndent()
        var resp = graphQuery(query)
        var data = resp.optJSONObject("data")

        if (data != null) {
            if (data.optString("alias1\$1") != null && data.optString("alias1\$1") == "QueryRoot") {
                return true
            }
        }


        query = """query aa#aa { __typename }"""
        resp = graphQuery(query)

        if (errorContains(resp, "Unexpected token \"END\"")) {
            return true
        }

        query = """
      query @skip {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Argument 'if' cannot be empty, so directive 'skip' has been ignored")) {
            return true
        }

        query = """
      query @doesnotexist {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "No DirectiveResolver resolves directive with name 'doesnotexist'")) {
            return true
        }

        query = ""
        resp = graphQuery(query)
        return errorContains(resp, "The query in the body is empty")
    }

    private fun engineWpGraphql(): Boolean {
        var query = ""
        var resp = graphQuery(query)
        if (errorContains(resp, "GraphQL Request must include at least one of those two parameters: \"query\" or \"queryId\"")) {
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

    private fun engineGqlGen(): Boolean {
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
    private fun engineGraphqlGo(): Boolean {
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

    private fun engineJuniper(): Boolean {
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
    private fun engineSangria(): Boolean {
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

    private fun engineFlutter(): Boolean {
        val query = """
      query {
        __typename @deprecated
    }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Directive \"deprecated\" may not be used on FIELD.")
    }

    private fun engineDianaJl(): Boolean {
        val query = """queryy { __typename }""".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \"queryy\"")
    }

    private fun engineStrawberry(): Boolean {
        val query = """
      query @deprecated {
        __typename
      }""".trimIndent()
        val resp = graphQuery(query)
        return (errorContains(resp, "Directive '@deprecated' may not be used on query.")  && resp.optJSONObject("data") != null)
    }

    private fun engineTartiflette(): Boolean {
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

    private fun engineTailcall(): Boolean {
        val query = """
      aa {
        __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)

        return errorContains(resp, "expected executable_definition")
    }

    private fun engineDgraph(): Boolean {
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

    private fun engineDirectus(): Boolean {
        val query = ""

        val resp = graphQuery(query)
        val errors = resp.optJSONArray("errors")
        return (JSONObject(errors.get(0)).optJSONObject("extensions")?.optString("code") == "INVALID_PAYLOAD")
    }

    private fun engineLighthouse(): Boolean {
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

    private fun engineAgoo(): Boolean {
        val query = """
      query {
        zzz
      }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "eval error")
    }
    private fun engineMercurius(): Boolean {
        val query = ""
        val resp = graphQuery(query)

        return errorContains(resp, "Unknown query")
    }
    private fun engineMorpheus(): Boolean {
        val query = """
      queryy {
          __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)

        return (errorContains(resp, "expecting white space") || errorContains(resp, "offset"))
    }
    private fun engineLacinia(): Boolean {
        val query = """
      query {
        inql
      }
    """.trimIndent()

        val resp = graphQuery(query)

        return errorContains(resp, "Cannot query field `inql' on type `QueryRoot'.")
    }

    // TODO
//    private fun engineJaal(): Boolean {
//        var query = """{}""".trimIndent()
//        var resp = self.graph_query(self.url, payload=query, operation='{}')
//
//    if errorContains(resp, 'must have a single query') or errorContains(resp, 'offset'):
//      return true
//
//    return false
//    }

  private fun engineCaliban(): Boolean {
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

  private fun engineAbsinthe(): Boolean {
    val query = """
        query {
            inql
        }
        """.trimIndent()

    val resp = graphQuery(query)

    return errorContains(resp, "Cannot query field \\\"inql\\\" on type \\\"RootQueryType\\\".")
}
  private fun engineGraphqlDotNet(): Boolean {
    val query = "query @skip { __typename }".trimIndent()
    val resp = graphQuery(query)
    return errorContains(resp, "Directive 'skip' may not be used on Query.")
  }

  private fun enginePgGraphql(): Boolean {
    val query = """query { __typename @skip(aa:true) }""".trimIndent()
    val resp = graphQuery(query)
    return errorContains(resp, "Unknown argument to @skip: aa")
  }

  private fun engineHotChocolate(): Boolean {
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

  private fun engineInigo(): Boolean {
      val query = """
        query  {
            __typename
        }
        """.trimIndent()
      val resp = graphQuery(query)

      return resp.optJSONArray("extensions") != null && "indigo" in resp.optJSONArray("extensions")
  }

  private fun engineBallerina(): Boolean {
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