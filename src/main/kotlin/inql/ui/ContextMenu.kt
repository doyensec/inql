package inql.ui

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import inql.InQL
import java.awt.Component
import java.awt.Toolkit
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*
import java.awt.Desktop
import java.net.URI
import java.net.URLEncoder
import inql.Config
import inql.Logger
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.LongSerializationPolicy
import com.google.gson.reflect.TypeToken
import java.lang.StringBuilder
import java.util.StringTokenizer

open class MenuAction(val name: String, val keyStroke: KeyStroke?, val action: (ActionEvent) -> Unit) :
    AbstractAction(name) {
    override fun actionPerformed(e: ActionEvent) {
        this.action(e)
    }
}

abstract class SendFromInqlHandler(val inql: InQL, val includeInqlScanner: Boolean = false) : MouseAdapter() {
    private val popup = JPopupMenu()

    // Actions
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
    protected val sendToVoyagerAction = MenuAction("Open in GraphQL Voyager (GraphQL schema visualizer)", null) {
        this.sendRequestToVoyager()
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
        if (config.getBoolean("integrations.voyager") == true) {
            actions.add(sendToVoyagerAction)
        }
        actions
    }
    protected val sendFromInqlActions = mutableListOf<MenuAction>(
        sendToIntruderAction,
        sendToRepeaterAction,
        *sendToEmbeddedToolActions().toTypedArray(),
    )
    abstract fun getRequest(): HttpRequest?
    override fun mousePressed(e: MouseEvent) {
        if (e.button != MouseEvent.BUTTON3) return // Right Click only
        this.popup.show(e.component, e.x, e.y)
    }

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
        Logger.error("Open URL: $url")

        val config = Config.getInstance()
        val useInternalBrowser = config.getString("integrations.browser.internal")?.equals("embedded") ?: false
        Logger.error("Should use internal browser: $useInternalBrowser")

        val browserCommandTemplate: String?
        if (useInternalBrowser) {
            browserCommandTemplate = config.getInternalBrowserCommand()
            if (browserCommandTemplate == null) {
                Logger.error("Could not find internal browser command")
                return
            }
        } else {
            browserCommandTemplate = config.getString("integrations.browser.external")
            if (browserCommandTemplate == null) {
                Logger.error("Could not find external browser command")
                return
            }
        }

        val browserCommand = browserCommandTemplate.format(url)
        Logger.error("Browser command: $browserCommand")

        // Java deprecated passing string to Runtime.getRuntime().exec() and requires an array of strings
        // but we want to support passing arguments with spaces in them, so we need to parse the command
        // using StringTokenizer and then convert it to an array of strings.
        val tokenizer = StringTokenizer(browserCommand)
        val commandArgs = mutableListOf<String>()

        while (tokenizer.hasMoreTokens()) {
            val token = tokenizer.nextToken()

            if (token.startsWith("\"")) {
                val builder = StringBuilder(token)
                while (tokenizer.hasMoreTokens() && !token.endsWith("\"")) {
                    builder.append(" ").append(tokenizer.nextToken())
                }
                commandArgs.add(builder.toString())
            } else {
                commandArgs.add(token)
            }
        }

        Logger.error("About to execute command: $commandArgs")
        val commandArray = commandArgs.toTypedArray()
        Logger.error("Executed command: $commandArray")

        try {
            Runtime.getRuntime().exec(commandArray)
        } catch (e: Exception) {
            Logger.error("Error executing command: $browserCommand")
        }
    }

    private fun sendRequestToEmbeddedTool(tool: String) {
        val request: HttpRequest = this.getRequest() ?: return

        // Pass GraphQL endpoint URL as 'server' parameter
        val server = request.url()
        val serverEncoded = URLEncoder.encode(server, "UTF-8")

        // Session is InQL header value (headerValue API does not exist, manually go through headers)
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
        Logger.error("Send Request to GraphiQL")
        sendRequestToEmbeddedTool("graphiql")
    }

    private fun sendRequestToVoyager() {
        Logger.error("Send Request to GraphQL Voyager")
        val request = this.getRequest() ?: return

        val server = request.url()
        val serverEncoded = URLEncoder.encode(server, "UTF-8")

        val session = request.headers().firstOrNull { it.name() == "InQL" }?.value() ?: "default"
        val sessionEncoded = URLEncoder.encode(session, "UTF-8")

        openURL("https://inql.burp/voyager?server=${serverEncoded}&session=${sessionEncoded}")
    }

    init {
        // Popup
        this.popup.add(this.sendToIntruderAction)
        this.popup.add(this.sendToRepeaterAction)
        this.popup.addSeparator()
        if (this.includeInqlScanner) {
            this.popup.add(this.sendToInqlScannerAction)
        }
        this.popup.add(this.sendToInqlAttackerAction)
        for (action in this.sendToEmbeddedToolActions()) {
            this.popup.add(action)
        }
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

    private val sendToInqlComponents = mutableListOf<JMenuItem>(
        BurpMenuItem(super.sendToInqlScannerAction),
        BurpMenuItem(super.sendToInqlAttackerAction),
    ).apply {
        for (action in super.sendToEmbeddedToolActions()) {
            this.add(BurpMenuItem(action))
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
        return this.sendToInqlComponents
    }

    override fun getRequest(): HttpRequest? {
        return this.request
    }
}
