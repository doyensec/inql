package inql.attackvector

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import inql.InQL
import inql.Logger
import inql.bruteforcer.ThrottledClient
import inql.graphql.formatting.Style
import inql.ui.BorderPanel
import inql.ui.CheckBox
import inql.ui.FlowPanel
import inql.ui.HtmlScrollPane
import inql.ui.MessageEditor
import inql.ui.Spinner
import inql.ui.applyEqualSplit
import inql.fingerprinter.EngineFingerprintReport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import javax.swing.SwingUtilities
import java.awt.FlowLayout
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.Toolkit
import java.awt.Desktop
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URI
import javax.swing.event.HyperlinkEvent
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JEditorPane
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTextField

class AttackVectorScanner(private val inql: InQL) : BorderPanel(), ActionListener {

    private val coroutineScope = CoroutineScope(Dispatchers.IO)
    private var scanJob: Job? = null

    private val urlField = JTextField()
    private val startButton = JButton("Start Scan").also {
        it.addActionListener(this@AttackVectorScanner)
        it.background = Style.ThemeColors.Accent
        it.foreground = Color.WHITE
        it.font = it.font.deriveFont(Font.BOLD)
        it.isBorderPainted = false
    }
    private val cancelButton = JButton("Cancel").also {
        it.isEnabled = false
        it.isVisible = false
        it.addActionListener {
            cancel()
        }
    }
    private val copyResultsButton = JButton("Copy Results").also {
        it.addActionListener {
            copyResultsToClipboard()
        }
    }

    private val maxDepthSpinner = Spinner("Max Depth", 1, 999, 1).also { it.setValue(10) }
    private val maxBatchSpinner = Spinner("Max Batch Size", 1, 999, 1).also { it.setValue(20) }
    private val maxComplexitySpinner = Spinner("Max Complexity", 1, 999, 1).also { it.setValue(100) }

    private val testCheckboxes = AttackVectorTestRegistry.allTests.associate { test ->
        test.id to CheckBox(test.name, selected = true)
    }

    private val results = mutableListOf<TestResult>()
    private val detailsPane = JEditorPane().apply {
        contentType = "text/html"
        isEditable = false
        border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
        addHyperlinkListener { e ->
            if (e.eventType == HyperlinkEvent.EventType.ACTIVATED) {
                try {
                    Desktop.getDesktop().browse(URI(e.url.toString()))
                } catch (ex: Exception) {
                    Logger.error("Failed to open link: ${ex.message}")
                }
            }
        }
    }
    private val evidenceViewer = MessageEditor(readOnly = true)
    private lateinit var bottomSplit: JSplitPane
    private lateinit var rightSplit: JSplitPane
    private val resultsTable = ScanResultsTable(results) { result ->
        showResultDetails(result)
    }

    private val requestEditor = Burp.Montoya.userInterface().createHttpRequestEditor()

    var url: String
        get() = urlField.text
        set(value) {
            urlField.text = value
        }

    var request: HttpRequest
        get() = requestEditor.request
        set(value) {
            requestEditor.request = value
        }

    fun focus() = inql.focusTab(this)

    fun loadFromRequest(req: HttpRequest) {
        url = req.url()
        request = req
        focus()
        urlField.requestFocus()
    }

    init {
        val helpPane = JEditorPane().apply {
            contentType = "text/html"
            text = """
                <h2>Attack Vector Scanner</h2>
                This tab probes a GraphQL endpoint for common security misconfigurations: public introspection,
                batching limits, GET query/mutation support, field suggestions, interface discovery, and more.
                <br/><br/>
                Select the tests to run, configure depth/batch/complexity limits, then click <b>Start Scan</b>.
                Select a result row to view details and the request/response that produced it.
            """.trimIndent()
            isEditable = false
        }

        val configPanel = buildConfigPanel()

        val actionPanel = BorderPanel().also {
            it.add(startButton, BorderLayout.WEST)
            it.add(cancelButton, BorderLayout.CENTER)
        }

        val urlFieldPanel = BorderPanel().also {
            it.add(JLabel("Target: "), BorderLayout.WEST)
            it.add(urlField, BorderLayout.CENTER)
            it.add(actionPanel, BorderLayout.EAST)
        }

        val reqEditorPanel = BorderPanel().also {
            it.add(urlFieldPanel, BorderLayout.NORTH)
            it.add(requestEditor.uiComponent(), BorderLayout.CENTER)
        }

        val leftTop = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JScrollPane(helpPane).apply {
                preferredSize = Dimension(0, 110)
            })
            add(configPanel)
        }

        val leftSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            leftTop,
            reqEditorPanel,
        ).apply {
            resizeWeight = 0.35
        }

        val resultsToolbar = BorderPanel().also {
            it.add(copyResultsButton, BorderLayout.EAST)
        }

        val detailsScroll = JScrollPane(detailsPane).apply {
            HtmlScrollPane.configure(this)
            border = BorderFactory.createTitledBorder("Details")
            preferredSize = Dimension(0, 100)
        }

        val resultsScroll = resultsTable.scrollPane.apply {
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(
                    BorderFactory.createLineBorder(ScanResultsTable.borderColorStatic()),
                    "Results",
                ),
                BorderFactory.createEmptyBorder(0, 0, 0, 0),
            )
        }

        bottomSplit = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            detailsScroll,
            evidenceViewer,
        ).apply {
            resizeWeight = 0.25
        }

        val resultsPanel = BorderPanel().also {
            it.add(resultsToolbar, BorderLayout.NORTH)
            it.add(resultsScroll, BorderLayout.CENTER)
            it.preferredSize = Dimension(0, resultsTable.defaultViewportHeight() + resultsToolbar.preferredSize.height + 28)
        }

        rightSplit = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            resultsPanel,
            bottomSplit,
        ).apply {
            resizeWeight = 0.3
            var initialized = false
            addComponentListener(object : java.awt.event.ComponentAdapter() {
                override fun componentResized(e: java.awt.event.ComponentEvent?) {
                    if (initialized || height <= 0) return
                    dividerLocation = resultsPanel.preferredSize.height.coerceIn(80, height - 80)
                    initialized = true
                }
            })
        }

        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSplit,
        ).apply {
            applyEqualSplit(0.5)
        }

        Burp.Montoya.userInterface().applyThemeToComponent(horizontalSplit)
        configureDetailsPane()
        evidenceViewer.isVisible = false
        add(horizontalSplit)
    }

    private fun configureDetailsPane() {
        detailsPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, false)
        detailsPane.contentType = "text/html"
        detailsPane.isEditable = false
    }

    private fun buildConfigPanel(): JPanel {
        val checksPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = Component.LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(4, 8, 4, 8)
            testCheckboxes.values.forEach { checkbox ->
                checkbox.component.alignmentX = Component.LEFT_ALIGNMENT
                add(checkbox.component)
            }
        }

        val limitsPanel = FlowPanel(FlowLayout.LEFT, 12).apply {
            border = BorderFactory.createEmptyBorder(4, 8, 8, 8)
            add(maxDepthSpinner)
            add(maxBatchSpinner)
            add(maxComplexitySpinner)
        }

        return JPanel().apply {
            layout = BorderLayout()
            border = BorderFactory.createTitledBorder("Scan Configuration")
            add(checksPanel, BorderLayout.CENTER)
            add(limitsPanel, BorderLayout.SOUTH)
        }
    }

    override fun actionPerformed(e: ActionEvent?) {
        Logger.debug("Attack Vector Scanner: start scan")
        scanJob?.cancel()
        scanJob = coroutineScope.launch {
            runScan()
        }
    }

    fun cancel() {
        scanJob?.cancel()
        SwingUtilities.invokeLater {
            applyCancelledScanState()
        }
    }

    private fun applyCancelledScanState() {
        val updated = resultsTable.getResults().map { result ->
            if (result.status == TestStatus.PENDING || result.status == TestStatus.RUNNING) {
                result.copy(
                    status = TestStatus.CANCELLED,
                    details = "Scan cancelled.",
                )
            } else {
                result
            }
        }
        resultsTable.setResults(updated)
        setScanning(false)
    }

    private suspend fun runScan() {
        val enabledTests = testCheckboxes.filter { it.value.isSelected() }.keys
        if (enabledTests.isEmpty()) {
            withContext(Dispatchers.Swing) {
                resultsTable.setResults(
                    listOf(
                        TestResult(
                            "Scan",
                            TestStatus.UNCERTAIN,
                            "No tests selected.",
                        ),
                    ),
                )
                showResultDetails(null)
            }
            return
        }

        withContext(Dispatchers.Swing) {
            setScanning(true)
        }

        try {
            coroutineContext.ensureActive()

            val targetUrl = resolveTargetUrl()
            if (targetUrl == null) {
                withContext(Dispatchers.Swing) {
                    resultsTable.setResults(
                        listOf(
                            TestResult(
                                "Scan",
                                TestStatus.UNCERTAIN,
                                "Target URL is empty or invalid. Enter a URL or load a GraphQL request first.",
                            ),
                        ),
                    )
                    showResultDetails(null)
                }
                return
            }

            val req = try {
                request.withService(
                    burp.api.montoya.http.HttpService.httpService(targetUrl),
                )
            } catch (e: Exception) {
                Logger.error("Attack Vector Scanner: invalid target URL '$targetUrl': ${e.message}")
                withContext(Dispatchers.Swing) {
                    resultsTable.setResults(
                        listOf(
                            TestResult(
                                "Scan",
                                TestStatus.UNCERTAIN,
                                "Invalid target URL: $targetUrl",
                            ),
                        ),
                    )
                    showResultDetails(null)
                }
                return
            }
            val client = ThrottledClient(req)
            val http = ScanHttpClient(req, client)
            val config = ScanConfig(
                maxDepth = maxDepthSpinner.getCommittedValue(),
                maxBatchSize = maxBatchSpinner.getCommittedValue(),
                maxComplexity = maxComplexitySpinner.getCommittedValue(),
                enabledTests = enabledTests,
            )
            val context = ScanContext(client, req, config, http)

            val enabledTestList = AttackVectorTestRegistry.allTests.filter { it.isEnabled(config) }
            val scanResults = enabledTestList.map { test ->
                TestResult(test.name, TestStatus.PENDING, "Waiting to run...")
            }.toMutableList()

            withContext(Dispatchers.Swing) {
                resultsTable.setResults(scanResults.toList())
                showResultDetails(null)
            }

            for (index in enabledTestList.indices) {
                coroutineContext.ensureActive()
                val test = enabledTestList[index]

                scanResults[index] = TestResult(test.name, TestStatus.RUNNING, "Running...")
                withContext(Dispatchers.Swing) {
                    resultsTable.setResults(scanResults.toList())
                }

                scanResults[index] = try {
                    test.run(context)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Logger.error("Attack vector test ${test.id} failed: ${e.message}")
                    TestResult(
                        test.name,
                        TestStatus.UNCERTAIN,
                        "Test failed with error: ${e.message ?: "unknown"}",
                    )
                }

                withContext(Dispatchers.Swing) {
                    resultsTable.setResults(scanResults.toList())
                }
            }

            withContext(Dispatchers.Swing) {
                if (scanResults.isNotEmpty() && resultsTable.table.selectionModel.isSelectionEmpty) {
                    resultsTable.table.selectionModel.setSelectionInterval(0, 0)
                }
            }
        } catch (_: CancellationException) {
            withContext(NonCancellable + Dispatchers.Swing) {
                applyCancelledScanState()
            }
        } finally {
            withContext(NonCancellable + Dispatchers.Swing) {
                setScanning(false)
            }
        }
    }

    private fun resolveTargetUrl(): String? {
        val fromField = url.trim()
        if (fromField.isNotBlank()) {
            return fromField
        }

        return try {
            val fromRequest = request.url().trim()
            if (fromRequest.isNotBlank()) fromRequest else null
        } catch (_: Exception) {
            null
        }
    }

    private fun setScanning(scanning: Boolean) {
        startButton.isEnabled = !scanning
        startButton.isVisible = !scanning
        cancelButton.isEnabled = scanning
        cancelButton.isVisible = scanning
    }

    private fun showResultDetails(result: TestResult?) {
        if (result == null) {
            EngineFingerprintReport.applyHtml(detailsPane, "")
            evidenceViewer.isVisible = false
            evidenceViewer.response.response = null
            collapseEvidencePanel()
            return
        }

        configureDetailsPane()
        EngineFingerprintReport.applyHtml(detailsPane, ScanResultDetailsRenderer.render(result))

        val evidence = result.evidence
        if (evidence != null) {
            evidenceViewer.isVisible = true
            evidenceViewer.request.request = evidence.request
            evidenceViewer.response.response = evidence.response
            restoreEvidencePanel()
        } else {
            evidenceViewer.isVisible = false
            evidenceViewer.response.response = null
            collapseEvidencePanel()
        }
    }

    private fun collapseEvidencePanel() {
        if (bottomSplit.height > 0) {
            bottomSplit.dividerLocation = bottomSplit.height - bottomSplit.dividerSize
        }
    }

    private fun restoreEvidencePanel() {
        bottomSplit.dividerLocation = (bottomSplit.height * 0.25).toInt().coerceAtLeast(80)
    }

    private fun copyResultsToClipboard() {
        val report = buildString {
            appendLine("InQL Attack Vector Scanner Results")
            appendLine("Target: ${urlField.text}")
            appendLine("=".repeat(60))
            for (result in resultsTable.getResults()) {
                appendLine(result.name)
                appendLine("  Status: ${result.status.label}")
                appendLine("  Details: ${result.details}")
                appendLine()
            }
        }
        val selection = java.awt.datatransfer.StringSelection(report)
        Toolkit.getDefaultToolkit().systemClipboard.setContents(selection, selection)
    }
}
