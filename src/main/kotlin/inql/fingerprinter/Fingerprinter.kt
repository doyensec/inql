package inql.fingerprinter

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import inql.InQL
import inql.bruteforcer.ThrottledClient
import inql.Logger
import inql.ui.BorderPanel
import inql.ui.DescriptionPane
import inql.ui.HtmlDocument
import inql.ui.HtmlScrollPane
import inql.ui.applyEqualSplit
import inql.ui.fitTopComponent
import kotlinx.coroutines.*
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.*

class Fingerprinter(private val inql: InQL) : BorderPanel(), ActionListener {

    private val coroutineScope = CoroutineScope(Dispatchers.IO)
    private var fingerPrinterJob: Job? = null
    private lateinit var graphQLClient: ThrottledClient
    private val resultsPane = JEditorPane()
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

        val helpPane = DescriptionPane(
            """
                <h2>Engine Fingerprinter</h2>
                This tab fingerprints the engine used by the GraphQL server. It sends various types of requests,
                including malformed ones, and compares the responses with those typically returned by known engines.
                <br/><br/>
                When a match is found, it shows the engine's default security posture and known vulnerabilities,
                based on data adapted from the <a href="https://github.com/nicholasaleks/graphql-threat-matrix">GraphQL Threat Matrix</a>.
            """.trimIndent(),
        )

        // Left section
        val leftSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(helpPane),
            reqEditorPanel,
        ).apply {
            fitTopComponent(helpPane)
        }

        showMessage("Engine Fingerprinter", "The results will appear here.")
        HtmlScrollPane.attachHyperlinkHandler(resultsPane)

        // Right section
        val rightSection = JScrollPane(resultsPane).also {
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

    private fun showResult(html: String) {
        SwingUtilities.invokeLater { HtmlDocument.show(resultsPane, html) }
    }

    private fun showMessage(title: String, message: String) {
        showResult(HtmlDocument.wrap("<h2>$title</h2><p>$message</p>"))
    }

    override fun actionPerformed(e: ActionEvent?) {
        Logger.debug("Initiate Attack handler fired")
        showMessage("Engine Fingerprinter", "Fingerprinting...")
        fingerPrinterJob = coroutineScope.launch {
            run()
        }
    }

    fun cancel() {
        fingerPrinterJob?.cancel()
    }

    private suspend fun run() {
        val req = this.request.withService(
            burp.api.montoya.http.HttpService.httpService(this.url),
        )
        graphQLClient = ThrottledClient(req)
        val probes = EngineProbes(graphQLClient)

        if (!probes.isGraphQLServer()) {
            showMessage(
                "Couldn't fingerprint server engine",
                """
                The server is not a GraphQL server or the server is not responding.<br>
                If you think this is a mistake, please report it to the InQL team at
                <a href="https://github.com/doyensec/inql/issues">https://github.com/doyensec/inql/issues</a>,
                or submit a pull request.
                """.trimIndent(),
            )
            return
        }

        val engineKey = probes.detectEngine()
        Logger.debug(engineKey.toString())
        val engine = engineKey?.let { ThreatMatrix.engine(it) }
        when {
            engine != null -> showResult(ThreatMatrixRenderer.render(engine))
            engineKey != null -> showMessage("Server engine found: $engineKey", "No threat matrix data is available for this engine.")
            else -> showMessage("Couldn't fingerprint server engine", "The server responds to GraphQL, but its engine was not recognized.")
        }
    }
}
