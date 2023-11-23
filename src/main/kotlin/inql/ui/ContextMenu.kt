package inql.ui

import burp.Browser
import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.LongSerializationPolicy
import com.google.gson.reflect.TypeToken
import inql.Config
import inql.InQL
import inql.Logger
import inql.externaltools.ExternalToolsService
import java.awt.Component
import java.awt.Toolkit
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.URLEncoder
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
abstract class SendFromInqlHandler(val inql: InQL, val includeInqlScanner: Boolean = false) : MouseAdapter() {
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
    protected val sendToInqlScannerAction = MenuAction("Generate queries with InQL Scanner", null) {
        this.sendRequestToInqlScanner()
    }
    protected val sendToInqlAttackerAction = MenuAction("Batch attack with InQL Attacker", null) {
        this.sendRequestToInqlAttacker()
    }
    protected val sendToGraphiqlAction = MenuAction("Open in GraphiQL (GraphQL IDE)", null) {
        this.sendRequestToGraphiQL()
    }
    protected val sendToPlaygroundAction = MenuAction("Open in GraphQL PlayGround", null) {
        this.sendRequestToPlayground()
    }
    protected val sendToAltairAction = MenuAction("Open in Altair IDE", null) {
        this.sendRequestToAltair()
    }
    protected val sendToVoyagerAction = MenuAction("Open in GraphQL Voyager (GraphQL schema visualizer)", null) {
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
    //         "integrations.playground" to false,
    //         "integrations.altair" to false,
    // Check those with: Config.getInstance().getBoolean("integrations.graphiql")
    protected val sendToEmbeddedToolActions = {
        val config = Config.getInstance()
        val actions = mutableListOf<MenuAction>()
        if (config.getBoolean("integrations.graphiql") == true) {
            actions.add(sendToGraphiqlAction)
        }
        if (config.getBoolean("integrations.playground") == true) {
            actions.add(sendToPlaygroundAction)
        }
        if (config.getBoolean("integrations.voyager") == true) {
            actions.add(sendToVoyagerAction)
        }
        if (config.getBoolean("integrations.altair") == true) {
            actions.add(sendToAltairAction)
        }
        actions
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
        sendToInqlScannerAction,
        sendToGraphiqlAction,
        sendToPlaygroundAction,
        sendToVoyagerAction,
        sendToAltairAction
    )
    abstract fun getRequest(): HttpRequest?
    abstract fun getText(): String
    override fun mousePressed(e: MouseEvent) {
        if (e.button == MouseEvent.BUTTON3) {    // Right Click only
            this.setContextActions()
            this.popup.show(e.component, e.x, e.y)
        }
    }

    // Populate the right click menu in InQL views (InQL Scanner, GraphQL editor view)
    // The context menus added by Burp itself **are not handled here** (e.g. Repeater - Raw editor - right click)
    // In order to add elements to Burp's menu (Extensions - InQL - ...), modify sendToInqlComponents in SendToInqlHandler class
    private fun setContextActions() {
        this.popup.removeAll()

        this.popup.add(this.sendToIntruderAction)
        this.popup.add(this.sendToRepeaterAction)
        this.popup.addSeparator()

        if (this.includeInqlScanner) {
            this.popup.add(this.sendToInqlScannerAction)
        }
        this.popup.add(this.sendToInqlAttackerAction)

        val embeddedActions = this.sendToEmbeddedToolActions()
        if (embeddedActions.isNotEmpty()) {
            this.popup.addSeparator()

            for (action in embeddedActions) {
                this.popup.add(action)
            }
        }
        this.popup.addSeparator()
        this.popup.add(this.saveToFileAction)
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

    private fun openURL(url: String) {
        Logger.info("Opening URL: $url")

        val config = Config.getInstance()
        val useInternalBrowser = config.getBoolean("integrations.browser.internal")?: true
        Logger.info("Should use internal browser? $useInternalBrowser")

        if (useInternalBrowser) {
            Browser.launchEmbedded(url)
        } else {
            Browser.launchExternal(url)
        }
    }

    private fun sendRequestToEmbeddedTool(tool: String) {
        // Ensure ExternalToolsService is running
        ExternalToolsService.startIfOff()

        val request: HttpRequest = this.getRequest() ?: return

        // Pass GraphQL endpoint URL as 'server' parameter
        val server = request.url()
        val serverEncoded = URLEncoder.encode(server, "UTF-8")

        // Session is InQL header value (headerValue API does not exist in Montoya API 1.0, manually go through headers)
        val session = request.headers().firstOrNull { it.name() == "InQL" }?.value() ?: "default"
        val sessionEncoded = URLEncoder.encode(session, "UTF-8")

        // Parse body as JSON (the LongSerialization is to make sure that large numbers are not parsed as Double)
        val body = request.bodyToString()
        val gson = GsonBuilder().setLongSerializationPolicy(LongSerializationPolicy.STRING).create()
        val parsed = gson.fromJson(body, object : TypeToken<Map<String, Any>>() {}.type) as Map<String, Any>

        // Get query from body
        val query = parsed["query"] as String
        val queryEncoded = URLEncoder.encode(query, "UTF-8")

        // Get variables from body
        val variables = parsed["variables"]
        val variablesEncoded = when (variables) {
            is String -> URLEncoder.encode(variables, "UTF-8")
            is Map<*, *> -> URLEncoder.encode(Gson().toJson(variables), "UTF-8")
            else -> null
        }

        openURL("https://inql.burp/${tool}?server=${serverEncoded}&session=${sessionEncoded}&query=${queryEncoded}&variables=${variablesEncoded}")
    }

    private fun sendRequestToGraphiQL() {
        Logger.debug("Send Request to GraphiQL")
        sendRequestToEmbeddedTool("graphiql")
    }

    private fun sendRequestToPlayground() {
        Logger.debug("Send Request to Playground")
        sendRequestToEmbeddedTool("playground")
    }

    private fun sendRequestToAltair() {
        Logger.debug("Send Request to Altair")
        sendRequestToEmbeddedTool("altair")
    }

    private fun sendRequestToVoyager() {
        Logger.debug("Send Request to GraphQL Voyager")
        val request = this.getRequest() ?: return

        // Ensure ExternalToolsService is running
        ExternalToolsService.startIfOff()

        val server = request.url()
        val serverEncoded = URLEncoder.encode(server, "UTF-8")

        val session = request.headers().firstOrNull { it.name() == "InQL" }?.value() ?: "default"
        val sessionEncoded = URLEncoder.encode(session, "UTF-8")

        openURL("https://inql.burp/voyager?server=${serverEncoded}&session=${sessionEncoded}")
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
    private fun sendToInqlComponents(): MutableList<JMenuItem> {
        return mutableListOf<JMenuItem>(
            BurpMenuItem(super.sendToInqlScannerAction),
            BurpMenuItem(super.sendToInqlAttackerAction)
        ).apply {
            for (action in super.sendToEmbeddedToolActions()) {
                this.add(BurpMenuItem(action))
            }
        }
    }

    private fun requestFromContext(event: ContextMenuEvent): HttpRequest? {
        val invocationType = event.invocationType()
        if (invocationType.containsScanIssues()) {
            val issues = event.selectedIssues()
            if (issues.size != 1) return null
            val requestResponses = issues[0].requestResponses()
            if (requestResponses.isEmpty()) return null
            return requestResponses[0].request()
        } else if (invocationType.containsHttpRequestResponses()) {
            val requestResponses = event.selectedRequestResponses()
            if (requestResponses.size != 1) return null
            return requestResponses[0].request()
        } else if (invocationType.containsHttpMessage()) {
            val msg = event.messageEditorRequestResponse().orElse(null) ?: return null
            return msg.requestResponse().request()
        }
        return null
    }

    override fun provideMenuItems(event: ContextMenuEvent): MutableList<JMenuItem>? {
        this.request = this.requestFromContext(event) ?: return null
        return this.sendToInqlComponents()
    }

    override fun getRequest(): HttpRequest? {
        return this.request
    }

    override fun getText(): String {
        return this.request.toString()
    }
}
