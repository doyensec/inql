package inql.scanner.scanconfig

import burp.Burp
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import inql.Logger
import inql.Profile
import inql.graphql.formatting.Style
import inql.scanner.Scanner
import inql.scanner.ScannerTab
import inql.ui.BorderPanel
import inql.ui.BoxPanel
import inql.ui.Label
import inql.utils.getTextAreaComponent
import inql.utils.withUpsertedHeaders
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Font
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.net.URI
import java.net.URISyntaxException
import javax.swing.*
import javax.swing.border.LineBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener


class ScanConfigView(val scannerTab: ScannerTab) : BorderPanel(10) {
    companion object {
        val PROFILE_NONE = Profile("None", "none", "")
        val PROFILE_NEW = Profile("(New)", "new", "")

        fun getDefaultRequest(): HttpRequest {
            return HttpRequest.httpRequest()
                .withMethod("POST")
                .withPath("/graphql")
                .withAddedHeader("Host", "example.com")
                .withDefaultHeaders()
                .withAddedHeader("Content-Type", "application/json")
        }
    }

    val scanner = scannerTab.scanner
    val inql = this.scanner.inql

    var file: String?
        get() = this.fileField.text
        set(s) {
            this.fileField.text = s
        }

    // Url Section
    private var urlChangeListener = UrlUnfocusListener(this)

    val urlField = JTextField().also {
        it.isFocusable = true
        it.putClientProperty("JTextField.placeholderText", "https://example.com/graphql")
        it.putClientProperty("JTextField.showClearButton", true)
        it.addKeyListener(UrlFieldKeyListener(this))
        it.addFocusListener(urlChangeListener)
        it.document.addUndoableEditListener { this.validateUrlAndFileInput() }
    }

    private val urlTextField = BorderPanel(10).also { it2 -> it2.add(BorderLayout.CENTER, this.urlField) }

    private val urlLabel = Label("GraphQL Endpoint URL", big = true).withPanel(5).also {
        toolTipText = "Provide the URL of the GraphQL endpoint, often includes the \"/graphql\" path"
    }

    // File Section
    private val fileChooser = ScannerFileChooser(this)
    private val fileField = JTextField().also {
        it.isFocusable = true
        it.putClientProperty("JTextField.placeholderText", "[Optional] Schema File (.json / .graphql)")
        it.putClientProperty("JTextField.showClearButton", true)
        it.addFocusListener(fileChooser)
        it.maximumSize = it.preferredSize
        it.minimumSize = Dimension(500, it.preferredSize.height)
        it.preferredSize = Dimension(500, it.preferredSize.height)
        it.document.addDocumentListener(TextFieldClearListener(this))
        it.document.addUndoableEditListener { this.validateUrlAndFileInput() }
    }

    private val fileLabel = Label("GraphQL Schema", big = true).withPanel(5).also {
        toolTipText = "InQL can query schema directly from GraphQL server. " +
                        "If a server does not allow introspection functionality, provide schema as a file (in JSON or SDL format). " +
                        "URL still needs to be provided to generate sample queries."
    }

    private val selectFileButton = JButton("Select File").also {
        it.addActionListener(this.fileChooser)
    }

    fun isValidUrl(urlText: String): Boolean {
        return try {
            val uri = URI(urlText.trim())
            uri.scheme != null && uri.host != null && uri.toURL() != null
        } catch (e: Exception) {
            false
        }
    }

    private fun validateUrlAndFileInput() {
        val urlText = urlField.text
        val isFileSelected = !fileField.text.isNullOrBlank()
        val isUrlEmpty = urlText.isNullOrBlank()
        val isUrlInvalid =  !isUrlEmpty && !isValidUrl(urlText)

        if ((isFileSelected && isUrlEmpty) || isUrlInvalid) {
            urlField.border = BorderFactory.createCompoundBorder(
                LineBorder(Color.RED),
                BorderFactory.createEmptyBorder(2, 4, 2, 4)
            )
            urlField.toolTipText = if (isUrlEmpty) {
                "This field cannot be empty"
            } else {
                "Invalid URL format"
            }
        } else {
            urlField.border = UIManager.getBorder("TextField.border")
            urlField.toolTipText = null
        }
    }

    // Request Template Section
    // - Profile stuff
    private val profileNameLabel = JLabel("None").also {
        it.font = it.font.deriveFont(Font.BOLD)
    }
    private val profileIdLabel = JLabel("")
    private val profilesComboBox = JComboBox<Profile>().also {
        it.maximumSize = it.preferredSize
        it.minimumSize = Dimension(300, it.preferredSize.height)
        it.preferredSize = Dimension(300, it.preferredSize.height)
        it.addActionListener { this.selectedProfileChanged() }
    }
    private val loadFromProfileBtn = JButton("Load").also {
        it.isEnabled = false
        it.addActionListener {
            this.loadSelectedProfile()
        }
    }
    private val saveToProfileBtn = JButton("Save").also {
        it.isEnabled = false
        it.addActionListener {
            this.saveSelectedProfile()
        }
    }
    private val deleteProfileBtn = JButton("Delete").also {
        it.isEnabled = false
        it.addActionListener {
            this.deleteSelectedProfile()
        }
    }
    private val requestTemplateLabel = Label("Request Template", big = true).withPanel(5).also {
        toolTipText ="Template of the HTTP request that will be used to send requests to the endpoint"
    }

    // - Request stuff
    private val updateHeadersBtn = JButton("Fetch latest headers").also {
        it.addActionListener {
            this.updateHeaders()
        }
    }
    private val startScanBtn = JButton("Analyze").also {
        it.foreground = Color.WHITE
        it.background = Style.ThemeColors.Accent
        it.font = it.font.deriveFont(Font.BOLD)
        it.isBorderPainted = false
        it.addActionListener { this.startScan() }
    }

    private val requestTemplateEditor = Burp.Montoya.userInterface().createHttpRequestEditor()
    var requestTemplate: HttpRequest
        get() = this.requestTemplateEditor.request
        set(r) {
            this.requestTemplateEditor.request = r
        }

    init {
        initUI()
        updateProfilesList()
        this.requestTemplateEditor.request = getDefaultRequest()
        this.requestTemplateEditor.getTextAreaComponent().addFocusListener(this.urlChangeListener)
        this.urlField.requestFocus()
    }

    private fun initUI() {
        val rootContainer = BoxPanel(BoxLayout.PAGE_AXIS)

        // 1. First block concerning URL
        rootContainer.let {
            //  1.1.1 First line, left - a big text label
            it.add(urlLabel)

            //  1.2 Second line - just a single Text field for URL
            it.add(urlTextField)
        }

        // A horizontal separator line between the blocks
        var separator = JSeparator().also { it.orientation = SwingConstants.HORIZONTAL }
        rootContainer.add(BorderPanel(3).also { it.add(separator) })

        // 2. Second block concerning file input
        rootContainer.add(fileLabel) // 2.1 First line - a big text label

        val fileInputPanel = BoxPanel(BoxLayout.LINE_AXIS).also {
            //it.border = BorderFactory.createEmptyBorder(5, 5, 5, 5)
            // 2.3.1 File field on the left
            it.add(this.selectFileButton)
            it.add(Box.createRigidArea(Dimension(10, 0)))
            // 2.3.2 Text field showing the selected file path (near the file field)
            it.add(this.fileField)
            it.add(Box.createHorizontalGlue())
        }
        rootContainer.add(BorderPanel(5, 10).also { it.add(fileInputPanel) })

        // A horizontal separator line between the blocks
        separator = JSeparator().also { it.orientation = SwingConstants.HORIZONTAL }
        rootContainer.add(BorderPanel(3).also { it.add(separator) })

        // 3. Third block with request template
        rootContainer.add(requestTemplateLabel)  // 2.1 First line - a big text label

        // Profile UI elements commented out. Needs rework.
        /*
        val profileLabelPanel = BoxPanel(BoxLayout.LINE_AXIS).also {
            it.add(JLabel("Current Profile:"))
            it.add(Box.createRigidArea(Dimension(5, 0)))
            it.add(profileNameLabel)
            it.add(Box.createRigidArea(Dimension(5, 0)))
            it.add(profileIdLabel)
        }
        rootContainer.add(BorderPanel(0, 5).also { it.add(profileLabelPanel) })
        */

        val buttonPanel = BoxPanel(BoxLayout.LINE_AXIS).also {
            /*
            it.add(this.profilesComboBox)
            it.add(Box.createRigidArea(Dimension(10, 0)))
            it.add(this.loadFromProfileBtn)
            it.add(Box.createRigidArea(Dimension(10, 0)))
            it.add(this.saveToProfileBtn)
            it.add(Box.createRigidArea(Dimension(10, 0)))
            it.add(this.deleteProfileBtn)
            it.add(Box.createHorizontalGlue())
            */
            it.add(startScanBtn)
            it.add(Box.createRigidArea(Dimension(10, 0)))
            it.add(updateHeadersBtn)
        }
        rootContainer.add(BorderPanel(10).also { it.add(buttonPanel) })

        this.add(BorderLayout.PAGE_START, rootContainer)
        this.add(BorderLayout.CENTER, requestTemplateEditor.uiComponent())
    }

    fun setBusy(on: Boolean) {
        this.urlField.isEnabled = !on
        this.fileField.isEnabled = !on
        this.selectFileButton.isEnabled = !on
        this.profilesComboBox.isEnabled = !on
        this.loadFromProfileBtn.isEnabled = !on
        this.saveToProfileBtn.isEnabled = !on
        this.deleteProfileBtn.isEnabled = !on
        this.updateHeadersBtn.isEnabled = !on
        this.startScanBtn.isEnabled = !on
        this.startScanBtn.text = if (on) "Loading..." else "Analyze"
    }

    fun startScan() {
        this.verifyAndReturnUrl() ?: return
        this.updateRequestFromUrlField()
        this.fixRequestNewlines()
        this.scannerTab.launchScan()
    }

    private fun updateHeaders() {
        val url = this.verifyAndReturnUrl() ?: return
        val headers = Scanner.fetchHeadersForHost(url.host) ?: return
        this.requestTemplate = this.requestTemplate.withUpsertedHeaders(headers)
    }

    fun updateProfilesList() {
        this.profilesComboBox.removeAllItems()
        this.profilesComboBox.addItem(PROFILE_NONE)
        this.profilesComboBox.toolTipText = "Select a profile"
        this.scannerTab.inql.getProfiles().forEach { this.profilesComboBox.addItem(it) }
        this.profilesComboBox.addItem(PROFILE_NEW)
    }

    private fun setLinkedProfile(p: Profile?) {
        this.scannerTab.linkedProfile = p
        if (p != null) {
            this.profileNameLabel.text = p.name
            this.profileIdLabel.text = if (p == PROFILE_NONE) "" else "(${p.id})"
        } else {
            this.profileNameLabel.text = "None"
            this.profileIdLabel.text = ""
        }
    }

    private fun loadSelectedProfile() {
        val selected = (this.profilesComboBox.selectedItem ?: return) as Profile
        this.scannerTab.loadFromProfile(selected)
        this.setLinkedProfile(selected)
        this.requestTemplateEditor.request = this.scannerTab.requestTemplate
    }

    private fun saveSelectedProfile() {
        val selected = (this.profilesComboBox.selectedItem ?: return) as Profile
        this.scannerTab.saveToProfile(selected)
        this.setLinkedProfile(selected)
    }

    private fun deleteSelectedProfile() {
        val isAlsoLinked = this.profilesComboBox.selectedItem == this.scannerTab.linkedProfile
        this.inql.deleteProfile(this.profilesComboBox.selectedItem as Profile)
        this.updateProfilesList()
        if (isAlsoLinked) {
            this.setLinkedProfile(null)
            this.profilesComboBox.selectedIndex = 0
        } else {
            this.profilesComboBox.selectedItem = this.scannerTab.linkedProfile
        }
    }

    private fun selectedProfileChanged() {
        val selected = (this.profilesComboBox.selectedItem ?: return) as Profile
        val profile: Profile?
        when (selected) {
            PROFILE_NEW -> {
                profile = this.newProfileDialog()
                if (profile == null) {
                    if (this.scannerTab.linkedProfile == null) {
                        this.profilesComboBox.selectedIndex = 0
                    } else {
                        this.profilesComboBox.selectedItem = this.scannerTab.linkedProfile
                    }
                    return
                }
                this.updateProfilesList()
                this.profilesComboBox.selectedItem = profile
                this.loadFromProfileBtn.isEnabled = true
                this.saveToProfileBtn.isEnabled = true
                this.deleteProfileBtn.isEnabled = true
                this.saveSelectedProfile()
            }

            PROFILE_NONE -> {
                this.setLinkedProfile(null)
                this.loadFromProfileBtn.isEnabled = false
                this.saveToProfileBtn.isEnabled = false
                this.deleteProfileBtn.isEnabled = false
            }

            else -> {
                this.loadFromProfileBtn.isEnabled = true
                this.saveToProfileBtn.isEnabled = true
                this.deleteProfileBtn.isEnabled = true
            }
        }
    }

    private fun newProfileDialog(): Profile? {
        val host = this.scannerTab.host
        if (host == null) {
            JOptionPane.showMessageDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                "The url field does not contain a valid URL.\nPlease enter a valid URL before creating a Profile.",
                "Incorrect URL",
                JOptionPane.ERROR_MESSAGE,
            )
            return null
        }
        val placeholder = this.inql.getAvailableProfileId(host)
        var name: String?
        do {
            name = JOptionPane.showInputDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                "Choose a name for the new Profile for ${this.scannerTab.host}",
                "New Profile",
                JOptionPane.QUESTION_MESSAGE,
                null,
                null,
                placeholder,
            ) as String?
            if (name == null) return null
        } while (name == "")
        return this.inql.createProfile(name!!, host)
    }

    fun reset() {
        this.setLinkedProfile(null)
        this.requestTemplate = getDefaultRequest()
    }

    private fun fixRequestNewlines() {
        val textarea = this.requestTemplateEditor.getTextAreaComponent()
        val lines = textarea.text.lines()
        if (lines[lines.size - 1].isNotEmpty()) {
            textarea.text += "\r\n\r\n"
        } else if (lines[lines.size - 2].isNotEmpty()) {
            textarea.text += "\r\n"
        }
    }

    fun verifyAndReturnUrl(): URI? {
        val textUrl = this.urlField.text.trim()
        if (!isValidUrl(textUrl)) {
            JOptionPane.showMessageDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                "Error parsing the target URL, make sure it's correctly formatted",
                "URL Error",
                JOptionPane.ERROR_MESSAGE,
                null,
            )
            return null
        }
        return URI.create(textUrl)
    }

    fun updateRequestFromUrlField() {
        val url = this.verifyAndReturnUrl() ?: return
        var path = url.path
        if (url.query?.isNotBlank() == true) path = "$path?${url.query}"
        this.requestTemplate = this.requestTemplate
            .withService(HttpService.httpService(url.toString()))
            .withUpdatedHeader("Host", url.host)
            .withPath(path)
            .withBody("")
    }

    fun updateUrlFieldFromRequest() {
        if(this.urlField.text.isBlank()) return
        this.urlField.text = this.requestTemplate.url()
    }

    class UrlUnfocusListener(private val view: ScanConfigView) : FocusAdapter() {
        override fun focusLost(e: FocusEvent) {
            when (e.component) {
                view.urlField -> view.updateRequestFromUrlField()
                view.requestTemplateEditor.getTextAreaComponent() -> view.updateUrlFieldFromRequest()
                else -> {
                    Logger.error("Unrecognized component: ${e.component}")
                    return
                }
            }
        }
    }

    class UrlFieldKeyListener(val view: ScanConfigView) : KeyAdapter() {
        override fun keyPressed(e: KeyEvent?) {
            super.keyPressed(e)
            if (e?.keyCode == KeyEvent.VK_ENTER) {
                Logger.info("Enter key pressed: starting scan")
                view.startScan()
            }
        }
    }

    class TextFieldClearListener(private val view: ScanConfigView) : DocumentListener {
        override fun insertUpdate(e: DocumentEvent?) {
            // Do nothing
        }

        override fun removeUpdate(e: DocumentEvent?) {
            view.file = null
        }

        override fun changedUpdate(e: DocumentEvent?) {
            // Do nothing
        }
    }
}
