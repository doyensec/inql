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
        KeyStroke.getKeyStroke(KeyEvent.VK_I, Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx)
    ) {
        this.sendRequestToIntruder()
    }
    protected val sendToRepeaterAction = MenuAction(
        "Send to Repeater",
        KeyStroke.getKeyStroke(KeyEvent.VK_R, Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx)
    ) {
        this.sendRequestToRepeater()
    }
    protected val sendToInqlScannerAction = MenuAction("Generate queries with InQL Scanner", null) {
        this.sendRequestToInqlScanner()
    }
    protected val sendToInqlAttackerAction = MenuAction("Batch attack with InQL Attacker", null) {
        this.sendRequestToInqlAttacker()
    }
    protected val sendToGraphiqlAction = MenuAction("Open in GraphiQL (embedded web IDE)", null) {
        this.sendRequestToGraphiQL()
    }
    protected val sendFromInqlActions = listOf<MenuAction>(
        sendToIntruderAction,
        sendToRepeaterAction,
        sendToInqlScannerAction,
        sendToInqlAttackerAction,
        sendToGraphiqlAction
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

    private fun sendRequestToGraphiQL() {
        ErrorDialog("GraphiQL is not implemented yet")
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
        this.popup.add(this.sendToGraphiqlAction)
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
        BurpMenuItem(super.sendToGraphiqlAction),
    )

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