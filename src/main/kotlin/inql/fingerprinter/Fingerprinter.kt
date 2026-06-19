package inql.fingerprinter

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import inql.InQL
import inql.bruteforcer.ThrottledClient
import inql.Logger
import inql.fingerprinter.EngineFingerprintReport
import inql.ui.BorderPanel
import inql.ui.HtmlScrollPane
import inql.ui.applyEqualSplit
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
    private lateinit var graphQLClient: ThrottledClient
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
<h2>References</h2>
- https://github.com/nicholasaleks/graphql-threat-matrix<br/><br/>
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
        val rightSection = JScrollPane(markdownEditorPane).also {
            HtmlScrollPane.configure(it)
        }



        // Main layout
        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSection,
        )
        horizontalSplit.applyEqualSplit(0.5)
        Burp.Montoya.userInterface().applyThemeToComponent(horizontalSplit)
        this.add(horizontalSplit)
    }

    private fun setMarkdown(markdown: String) {
        EngineFingerprintReport.applyHtml(markdownEditorPane, EngineFingerprintReport.htmlForMarkdown(markdown))
    }

    private fun setMarkdownFromUrl(enginedetails: Helpers.Companion.EngineDetails) {
        setMarkdown(EngineFingerprintReport.markdownForEngine(enginedetails))
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
        val req = this.request.withService(
            burp.api.montoya.http.HttpService.httpService(this.url),
        )
        graphQLClient = ThrottledClient(req)
        val probes = EngineProbes(graphQLClient)

        if (probes.isGraphQLServer()) {
            val engine = probes.detectEngine()
            Logger.debug(engine.toString())
            if (engine != null) {
                Helpers.engines[engine]?.let { setMarkdownFromUrl(it) }
            } else {
                setMarkdown("# Couldn't fingerprint server engine")
            }
        } else {
          var markdown = """
# Couldn't fingerprint server engine
The server is not a GraphQL server or the server is not responding.<br/>
If you think this is a mistake, please report it to the InQL team.<br/>
https://github.com/inql/inql/issues<br/>
If you want to help us fix this, please submit a pull request.<br/>
          """
          setMarkdown(markdown)
        }
    }
}