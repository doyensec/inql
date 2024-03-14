package inql.scanner.scanconfig

import burp.Burp
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.HttpHeader
import fetchHeadersForHost
import inql.Logger
import inql.scanner.ScannerTab
import inql.session.Session
import inql.ui.BorderPanel
import inql.ui.BoxPanel
import inql.ui.Label
import inql.ui.MultilineLabel
import inql.utils.*
import isValidUrl
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Font
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.net.URI
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class ScanConfigView(private val scannerTab: ScannerTab) : BorderPanel(10) {
    val scanner = scannerTab.scanner
    val inql = this.scanner.inql

    /*
     * "1. URL of the GraphQL endpoint"
     */
    private val urlField = JTextField().apply {
        isFocusable = true
        putClientProperty("JTextField.placeholderText", "https://example.com/graphql")
        putClientProperty("JTextField.showClearButton", true)
        addKeyPressedListener { e ->
            if (e?.keyCode == KeyEvent.VK_ENTER) {
                Logger.info("Enter key pressed: starting scan")
                startScan()
            }
        }
        document.addDocumentListener(object: DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = urlFieldUpdatedHandler()
            override fun removeUpdate(e: DocumentEvent?) = urlFieldUpdatedHandler()
            override fun changedUpdate(e: DocumentEvent?) = urlFieldUpdatedHandler()
        })
    }

    var url: String?
        get() = urlField.text.trim().takeIf { isValidUrl(it) }
        set(value) {
            if (urlField.text != value) {
                urlField.text = value
                urlFieldUpdatedHandler()
            }
        }


    /*
     * "2. (Optional) GraphQL schema file (JSON or SDL format)"
     */
    private val fileChooser = ScannerFileChooser(this)
    private val selectFileButton = JButton("Select File").apply { addActionListener(fileChooser) }
    private val fileField = JTextField().apply {
        isFocusable = true
        putClientProperty("JTextField.placeholderText", "GraphQL introspection schema in JSON format")
        putClientProperty("JTextField.showClearButton", true)
        addFocusListener(fileChooser)
        maximumSize = preferredSize
        minimumSize = Dimension(500, preferredSize.height)
        preferredSize = Dimension(500, preferredSize.height)
        addRemoveUpdateListener { file = null }
    }

    var file: String?
        get() = fileField.text.takeIf { it.isNotBlank() }
        set(value) { fileField.text = value }


    /*
     * "3. Session Configuration"
     */
    private val GRAPHQL_HEADERS = listOf(
        "content-type" to "application/json",
        "content-type" to "application/graphql",
    )
    private val updateHeadersBtn = JButton("Fetch Latest Headers").apply {
        addActionListener {
            val url = verifyAndReturnUrl() ?: return@addActionListener
            fetchHeadersForHost(url.host, url.path, GRAPHQL_HEADERS)?.let { headers ->
                sessionYaml = Session.updateTemplateWithHeaders(sessionYaml, headers)
            }
        }
    }

    private val startScanBtn = JButton("Analyze").apply {
        foreground = Color.WHITE
        background = Color(255, 88, 18)
        font = font.deriveFont(Font.BOLD)
        isBorderPainted = false
        addActionListener { startScan() }
    }

    private val sessionConfigEditor = Burp.Montoya.userInterface().createRawEditor().apply {
        uiComponent().addKeyListener(object: KeyAdapter() {
            override fun keyReleased(e: KeyEvent?) = sessionConfigUpdatedHandler()
        })
        uiComponent().addFocusLostListener { sessionConfigUpdatedHandler() }
    }

    var sessionYaml: String
        get() = this.sessionConfigEditor.contents.toString()
        set(text) {
            Logger.debug("Setting session YAML to: $text")
            this.sessionConfigEditor.contents = ByteArray.byteArray(text)
            sessionConfigUpdatedHandler()
        }

    // There are two data items that need to be kept in sync:
    //  1. The URL field should match `graphqlEndpoint` in the session YAML
    //  2. The tab name should match the `sessionId` in the session YAML
    // This is achieved via DocumentListener / FocusListener and the following handlers.

    private fun urlFieldUpdatedHandler() = url?.let {
        if (isValidUrl(it))
            sessionYaml = Session.updateTemplateWithUrl(sessionYaml, it)
    } ?: Unit

    private fun sessionConfigUpdatedHandler() {
        val newUrl = Session.getUrlOutOfTemplate(sessionYaml) ?: ""
        if (newUrl != url && isValidUrl(newUrl)) {
            url = newUrl
        }

        val newSessionId = Session.getSessionIdOutOfTemplate(sessionYaml) ?: ""
        if (newSessionId != scannerTab.getTabTitle()) {
            scannerTab.setTabTitle(newSessionId)
        }
    }

    private fun updateUrlOrError() {
        val urlValue = url
        if (urlValue != null && isValidUrl(urlValue)) {
            sessionYaml = Session.updateTemplateWithUrl(sessionYaml, urlValue)
        } else {
            JOptionPane.showMessageDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                "The URL is not valid",
                "URL Error",
                JOptionPane.ERROR_MESSAGE,
                null,
            )
        }
    }

    private fun startScan() {
        updateUrlOrError()
        scannerTab.launchScan()
    }

    /*
     * Constructor
     */
    init {
        initUI()
        this.sessionYaml = Session.createEmptyTemplate()
        this.urlField.requestFocus()
    }

    private fun initUI() {
        val rootContainer = BoxPanel(BoxLayout.PAGE_AXIS)

        // 1. First block concerning URL
        with(rootContainer) {
            //  1.1.1 First line, left - a big text label
            add(Label("1. URL of the GraphQL endpoint", big = true).withPanel(5))
            add(MultilineLabel("Provide the URL of the GraphQL endpoint, often includes the \"/graphql\" path"))

            //  1.2 Second line - just a single Text field for URL
            add(BorderPanel(10).apply { add(BorderLayout.CENTER, urlField) })
        }

        // A horizontal separator line between the blocks
        var separator = JSeparator().apply { orientation = SwingConstants.HORIZONTAL }
        rootContainer.add(BorderPanel(3).apply { add(separator) })

        // 2. Second block concerning file input
        with(rootContainer) {
            // 2.1 First line - a big text label
            add(Label("2. (Optional) GraphQL schema file (JSON or SDL format)", big = true).withPanel(5))
            add(
                MultilineLabel(
                    "InQL can query schema directly from GraphQL server. " +
                        "If a server does not allow introspection functionality, provide schema as a file (in JSON or SDL format). " +
                        "URL still needs to be provided to generate sample queries.",
                ),
            )
        }

        val fileInputPanel = BoxPanel(BoxLayout.LINE_AXIS).apply {
            border = BorderFactory.createEmptyBorder(5, 5, 5, 5)
            // 2.3.1 File field on the left
            add(selectFileButton)
            add(Box.createRigidArea(Dimension(10, 0)))
            // 2.3.2 Text field showing the selected file path (near the file field)
            add(fileField)
            add(Box.createHorizontalGlue())
        }
        rootContainer.add(fileInputPanel)

        // A horizontal separator line between the blocks
        separator = JSeparator().apply { orientation = SwingConstants.HORIZONTAL }
        rootContainer.add(BorderPanel(3).apply { add(separator) })

        // 3. Third block with session configuration
        with(rootContainer) {
            // 3.1 First line - a big text label
            add(Label("3. Session Configuration", big = true).withPanel(5))
            // 3.2 Second line - smaller text with explanation
            add(MultilineLabel("Edit YAML to customize the session configuration. Use 'Fetch Latest Headers' button to auto-load headers for the URL from Burp Suite history."))
        }

        val buttonPanel = BoxPanel(BoxLayout.LINE_AXIS).apply {
            add(Box.createHorizontalGlue())
            add(updateHeadersBtn)
            add(Box.createRigidArea(Dimension(10, 0)))
            add(startScanBtn)
        }
        rootContainer.add(BorderPanel(10).apply { add(buttonPanel) })

        add(BorderLayout.PAGE_START, rootContainer)
        add(BorderLayout.CENTER, sessionConfigEditor.uiComponent())
    }

    fun setBusy(on: Boolean) {
        urlField.isEnabled = !on
        fileField.isEnabled = !on
        selectFileButton.isEnabled = !on
        updateHeadersBtn.isEnabled = !on
        startScanBtn.isEnabled = !on
        startScanBtn.text = if (on) "Loading..." else "Analyze"
    }

    private fun verifyAndReturnUrl(): URI? {
        val url = this.urlField.text.trim()
        if (isValidUrl(url)) {
            return URI.create(url)
        } else {
            JOptionPane.showMessageDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                "The URL is not valid",
                "URL Error",
                JOptionPane.ERROR_MESSAGE,
                null,
            )
            return null
        }
    }

//    fun updateRequestFromUrlField() {
//        url?.let {
//            sessionYaml = Session.updateTemplateWithUrl(sessionYaml, it)
//        }
//
//        val url = this.verifyAndReturnUrl() ?: return
//        var path = url.path
//        if (url.query?.isNotBlank() == true) path = "$path?${url.query}"
//        this.requestTemplate = this.requestTemplate
//            .withService(HttpService.httpService(url.toString()))
//            .withUpdatedHeader("Host", url.host)
//            .withPath(path)
//            .withBody("")
//    }

}
