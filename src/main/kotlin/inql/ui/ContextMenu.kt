package inql.ui

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.InvocationType
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import inql.graphql.GraphQLRequestTransformException
import inql.graphql.GraphQLRequestTransformer
import inql.graphql.GraphQLTransportFormat
import inql.history.HistoryHostKey
import inql.history.HistoryTracker
import inql.Config
import inql.InQL
import inql.Logger
import inql.externaltools.ExternalToolsService
import inql.externaltools.ExternalToolsService.Companion.sendRequestToEmbeddedTool
import inql.schema.corrections.GraphQLTypeSuggestionParser
import javax.swing.SwingUtilities
import java.awt.Component
import java.awt.Toolkit
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*

open class MenuAction(val name: String, val keyStroke: KeyStroke?, val action: (ActionEvent) -> Unit) :
    AbstractAction(name) {
    override fun actionPerformed(e: ActionEvent) {
        this.action(e)
    }
}

/*
    This class provides the Context Menu that is opened when the user Right-Clicks inside InQL (e.g. in the Scanner Tab Results
    The actions have associated Keyboard Shortcuts so that standard Burp shortcuts can be used from InQL

    This class is also extended below from SendToInqlHandler which instead provides the Extension Context Menu "InQL >" for
    Burp's standard context menu in other Burp tools (Scanner, Proxy, etc).
 */
abstract class SendFromInqlHandler(val inql: InQL, val includeInqlScanner: Boolean = false, val includeSaveToFile: Boolean = true) : MouseAdapter() {
    private val popup = JPopupMenu()

    // ===== Actions associated with Menu Items

    protected val sendToIntruderAction = MenuAction(
        "Send to Intruder",
        KeyStroke.getKeyStroke(KeyEvent.VK_I, Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx),
    ) {
        this.sendRequestToIntruder()
    }
    protected val sendToRepeaterAction = MenuAction(
        "Send to Repeater",
        KeyStroke.getKeyStroke(KeyEvent.VK_R, Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx),
    ) {
        this.sendRequestToRepeater()
    }
    protected val sendToInqlScannerAction = MenuAction("Analyse in Introspection Scanner", null) {
        this.sendRequestToInqlScanner()
    }
    protected val sendToInqlAttackerAction = MenuAction("Open in Batch Queries", null) {
        this.sendRequestToInqlAttacker()
    }
    protected val sendToInqlFingerprinterAction = MenuAction("Open in Engine Fingerprinter", null) {
        this.sendRequestToInqlFingerprinter()
    }
    protected val sendToGraphiqlAction = MenuAction("Open in GraphiQL", null) {
        this.sendRequestToGraphiQL()
    }
    protected val sendToVoyagerAction = MenuAction("Open in GraphQL Voyager", null) {
        this.sendRequestToVoyager()
    }

    protected val saveToFileAction = MenuAction("Save to file", null) {
        val filechooser = JFileChooser()
        if (filechooser.showSaveDialog(Burp.Montoya.userInterface().swingUtils().suiteFrame()) == JFileChooser.APPROVE_OPTION) {
            val file = filechooser.selectedFile
            file.writeText(this.getText())
        }
    }

    // A list of optional actions to include based on config values:
    //         "integrations.graphiql" to true,
    //         "integrations.voyager" to true,
    // Check those with: Config.getInstance().getBoolean("integrations.graphiql")
    protected val sendToEmbeddedToolActions = mutableListOf<MenuAction>().apply {
        val config = Config.getInstance()
        if (config.getBoolean("integrations.graphiql") == true) {
            this.add(sendToGraphiqlAction)
        }
        if (config.getBoolean("integrations.voyager") == true) {
            this.add(sendToVoyagerAction)
        }
    }

    /* The following list is currently used for:
     - Enable/Disable (grey-out) context menu items when the user
        right-clicks something that is not actually a GraphQL item, e.g. a point of interest in the scanner results.
     - Provide Keyboard Shortcuts (CTRL+R, CTRL+I, etc)
     */
    protected val sendFromInqlActions = mutableListOf<MenuAction>(
        sendToIntruderAction,
        sendToRepeaterAction,
        sendToInqlAttackerAction,
        sendToInqlFingerprinterAction,
        sendToInqlScannerAction,
        sendToGraphiqlAction,
        sendToVoyagerAction
    )
    abstract fun getRequest(): HttpRequest?
    abstract fun getText(): String
    override fun mousePressed(e: MouseEvent) {
        if (e.button == MouseEvent.BUTTON3) {    // Right Click only
            this.setContextActions()
            this.popup.show(e.component, e.x, e.y)
        }
    }

    /** Subclasses may add items (e.g. Copy) after the standard entries. */
    protected open fun appendBottomContextMenuItems(popup: JPopupMenu) {}

    // Populate the right click menu in InQL views (InQL Scanner, GraphQL editor view)
    // The context menus added by Burp itself **are not handled here** (e.g. Repeater - Raw editor - right click)
    // In order to add elements to Burp's menu (Extensions - InQL - ...), modify sendToInqlComponents in SendToInqlHandler class
    private fun setContextActions() {
        this.popup.removeAll()

        if (this.popup.componentCount > 0) {
            this.popup.addSeparator()
        }

        this.popup.add(this.sendToIntruderAction)
        this.popup.add(this.sendToRepeaterAction)
        this.popup.addSeparator()

        if (this.includeInqlScanner) {
            this.popup.add(this.sendToInqlScannerAction)
        }
        this.popup.add(this.sendToInqlAttackerAction)
        this.popup.add(this.sendToInqlFingerprinterAction)

        val embeddedActions = this.sendToEmbeddedToolActions
        if (embeddedActions.isNotEmpty()) {
            this.popup.addSeparator()

            for (action in embeddedActions) {
                this.popup.add(action)
            }
        }

        if (this.includeSaveToFile) {
            this.popup.addSeparator()
            this.popup.add(this.saveToFileAction)
        }

        appendBottomContextMenuItems(this.popup)
    }

    // ===== Convenience methods for the actions
    private fun sendRequestToIntruder() {
        Burp.Montoya.intruder().sendToIntruder(this.getRequest() ?: return)
    }

    private fun sendRequestToRepeater() {
        Burp.Montoya.repeater().sendToRepeater(this.getRequest() ?: return)
    }

    private fun sendRequestToInqlScanner() {
        inql.scanner.newTabFromRequest(this.getRequest() ?: return)
    }

    private fun sendRequestToInqlAttacker() {
        inql.attacker.loadFromRequest(this.getRequest() ?: return)
    }

    private fun sendRequestToInqlFingerprinter() {
        inql.fingerprinter.loadFromRequest(this.getRequest() ?: return)
    }

    private fun sendRequestToGraphiQL() {
        Logger.debug("Send Request to GraphiQL")
        sendRequestToEmbeddedTool(this.getRequest(), ExternalToolsService.Companion.TOOL.TOOL_GRAPHIQL)
    }

    private fun sendRequestToVoyager() {
        Logger.debug("Send Request to Voyager")
        sendRequestToEmbeddedTool(this.getRequest(), ExternalToolsService.Companion.TOOL.TOOL_VOYAGER)
    }

    fun setEnabled(enabled: Boolean) {
        this.sendFromInqlActions.forEach {
            it.isEnabled = enabled
        }
    }

    fun addRightClickHandler(c: Component) {
        c.addMouseListener(this)
    }

    fun addKeyboardShortcutHandler(c: JComponent) {
        for (action in this.sendFromInqlActions) {
            if (action.keyStroke == null) continue
            c.inputMap.put(action.keyStroke, action.name)
            c.actionMap.put(action.name, action)
        }
    }
}

class SendToInqlHandler(inql: InQL) : SendFromInqlHandler(inql), ContextMenuItemsProvider {
    class BurpMenuItem(action: MenuAction) : JMenuItem(action.name) {
        init {
            this.addActionListener {
                action.action(it)
            }
        }
    }

    private var request: HttpRequest? = null

    // This only sets Right Click handlers for the Burp's own menus. Menus added by InQL are handled
    // in setContextActions()
    private val extractHistorySchemaAction = MenuAction("Extract Schema from History", null) {
        this.extractGraphQLSchemaFromHost()
    }

    private fun typeRenameSubmenu(actions: List<MenuAction>): JMenu? {
        if (actions.isEmpty()) return null
        return JMenu("Add type correction").also { submenu ->
            for (action in actions) {
                submenu.add(BurpMenuItem(action))
            }
        }
    }

    private fun transformRequestSubmenu(
        editor: MessageEditorHttpRequestResponse,
    ): JMenu? {
        val request = editor.requestResponse().request()
        if (GraphQLRequestTransformer.parsePayload(request) == null) return null

        return JMenu("Transform Request to:").also { submenu ->
            for (format in GraphQLTransportFormat.entries.filter { it.showInTransformMenu() }) {
                submenu.add(
                    BurpMenuItem(
                        MenuAction(format.menuLabel!!, null) {
                            transformRequestInEditor(editor, format)
                        },
                    ),
                )
            }
        }
    }

    private fun transformRequestInEditor(
        editor: MessageEditorHttpRequestResponse,
        target: GraphQLTransportFormat,
    ) {
        val request = editor.requestResponse().request()
        try {
            val transformed = GraphQLRequestTransformer.transform(request, target)
            editor.setRequest(transformed)
        } catch (e: GraphQLRequestTransformException) {
            showTransformError(e.message ?: "Request transformation failed.")
        } catch (_: UnsupportedOperationException) {
            showTransformError("This request cannot be edited in the current view.")
        } catch (e: Exception) {
            showTransformError("Request transformation failed: ${e.message}")
        }
    }

    private fun showTransformError(message: String) {
        SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                message,
                "InQL",
                JOptionPane.WARNING_MESSAGE,
            )
        }
    }

    private fun sendToInqlComponents(
        typeRenameActions: List<MenuAction> = emptyList(),
        messageEditor: MessageEditorHttpRequestResponse? = null,
    ): MutableList<Component> {
        return mutableListOf<Component>(
            BurpMenuItem(super.sendToInqlScannerAction),
            BurpMenuItem(super.sendToInqlAttackerAction),
            BurpMenuItem(super.sendToInqlFingerprinterAction),
        ).apply {
            for (action in super.sendToEmbeddedToolActions) {
                this.add(BurpMenuItem(action))
            }
            if (this@SendToInqlHandler.selectedHost != null) {
                this.add(BurpMenuItem(extractHistorySchemaAction))
            }
            typeRenameSubmenu(typeRenameActions)?.let { add(it) }
            messageEditor?.let { editor ->
                transformRequestSubmenu(editor)?.let { submenu ->
                    add(JSeparator())
                    add(submenu)
                }
            }
        }
    }

    private var selectedHost: String? = null

    private fun extractGraphQLSchemaFromHost() {
        val host = this.selectedHost ?: return
        if (!HistoryTracker.isRunning()) {
            HistoryTracker.start(inql)
        }
        HistoryTracker.extractSchemaForHost(host)
    }

    private fun hostFromContext(event: ContextMenuEvent): String? {
        if (event.invocationType() == InvocationType.SITE_MAP_TREE) {
            val requestResponses = event.selectedRequestResponses()
            if (requestResponses.isNotEmpty()) {
                return HistoryHostKey.fromRequest(requestResponses[0].request())
            }
        }
        val request = requestFromContext(event)
        if (request != null) {
            return HistoryHostKey.fromRequest(request)
        }
        return null
    }

    private fun requestFromContext(event: ContextMenuEvent): HttpRequest? {
        val invocationType = event.invocationType()
        if (invocationType.containsHttpRequestResponses()) {
            val requestResponses = event.selectedRequestResponses()
            if (requestResponses.size != 1) return null
            return requestResponses[0].request()
        }
        if (invocationType.containsHttpMessage()) {
            val msg = event.messageEditorRequestResponse().orElse(null) ?: return null
            return msg.requestResponse().request()
        }
        return null
    }

    private fun responseFromContext(event: ContextMenuEvent): HttpResponse? {
        val invocationType = event.invocationType()
        if (invocationType.containsHttpRequestResponses()) {
            val requestResponses = event.selectedRequestResponses()
            if (requestResponses.size != 1) return null
            return requestResponses[0].response()
        }
        if (invocationType.containsHttpMessage()) {
            val msg = event.messageEditorRequestResponse().orElse(null) ?: return null
            return msg.requestResponse().response()
        }
        return null
    }

    private fun typeRenameActionsFromResponse(
        request: HttpRequest,
        response: HttpResponse,
    ): List<MenuAction> {
        val suggestions = GraphQLTypeSuggestionParser.parseTypeRenameSuggestions(response.bodyToString())
        if (suggestions.isEmpty()) return emptyList()
        return suggestions.map { suggestion ->
            MenuAction(
                "${suggestion.wrongType} → ${suggestion.suggestedType}",
                null,
            ) {
                applyTypeRenameCorrection(request, suggestion.wrongType, suggestion.suggestedType)
            }
        }
    }

    private fun applyTypeRenameCorrection(request: HttpRequest, wrongType: String, suggestedType: String) {
        val host = HistoryHostKey.fromRequest(request)
        val applied = inql.scanner.applyTypeRenameCorrection(request, host, wrongType, suggestedType)
        if (applied) return
        SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(
                Burp.Montoya.userInterface().swingUtils().suiteFrame(),
                "Could not apply type rename for $host.\n" +
                    "Open or extract a schema for this host in InQL Scanner first.",
                "InQL",
                JOptionPane.WARNING_MESSAGE,
            )
        }
    }

    private fun requestFromIssues(event: AuditIssueContextMenuEvent): HttpRequest? {
        val invocationType = event.invocationType()
        if (invocationType.containsScanIssues()) {
            val issues = event.selectedIssues()
            if (issues.size != 1) return null
            val requestResponses = issues[0].requestResponses()
            if (requestResponses.isEmpty()) return null
            return requestResponses[0].request()
        }
        return null
    }

    override fun provideMenuItems(event: ContextMenuEvent): MutableList<Component>? {
        this.selectedHost = this.hostFromContext(event)
        if (event.invocationType() == InvocationType.SITE_MAP_TREE && this.selectedHost != null) {
            return mutableListOf(BurpMenuItem(extractHistorySchemaAction))
        }
        val request = this.requestFromContext(event) ?: return null
        this.request = request
        val typeRenameActions = responseFromContext(event)?.let { response ->
            typeRenameActionsFromResponse(request, response)
        } ?: emptyList()
        val messageEditor = event.messageEditorRequestResponse()
            .filter { it.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST }
            .orElse(null)
        return this.sendToInqlComponents(typeRenameActions, messageEditor)
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): MutableList<Component> {
        if (event == null) return mutableListOf()
        this.selectedHost = null
        this.request = this.requestFromIssues(event) ?: return mutableListOf()
        return this.sendToInqlComponents()
    }

    override fun getRequest(): HttpRequest? {
        return this.request
    }

    override fun getText(): String {
        return this.request.toString()
    }
}
