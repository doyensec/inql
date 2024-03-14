package inql.scanner

import burp.api.montoya.http.message.requests.HttpRequest
import inql.InQL
import inql.Logger
import inql.session.SessionManager
import inql.ui.EditableTabTitle
import inql.ui.EditableTabbedPane
import javax.swing.BorderFactory

class Scanner(val inql: InQL) : EditableTabbedPane() {
    private val tabFactory = ScannerTabFactory(this)

    init {
        this.border = BorderFactory.createEmptyBorder(5, 0, 0, 0)
        this.setTabComponentFactory(this.tabFactory)
        this.addTitleChangeListener { this.tabTitleChangeListener(it) }
        this.newTab()
    }

    override fun closeTab(idx: Int) {
        val tab = this.tabbedPane.getComponentAt(idx) as ScannerTab
        tab.session?.let { session ->
            SessionManager.removeSession(session.sessionId)
        }
        super.closeTab(idx)
        tab.onClose()
    }

    private fun tabTitleChangeListener(e: EditableTabTitle) {
        val scannerTab = e.component as ScannerTab
        // Prevent empty titles
        var title = e.text
        if (title.trim() == "") {
            title = "${scannerTab.id}"
        }
        scannerTab.session?.let { session ->
            // Attempt to update session ID, but revert tab title to old value if this fails
            if (!SessionManager.updateSessionId(session.sessionId, title)) {
                Logger.error("Failed to update session ID")
                title = session.sessionId
            }
        }
        e.text = title
    }

    fun newTabFromRequest(req: HttpRequest) {
        val tab = this.newTab() as ScannerTab
        tab.updateFromHttpRequest(req)
        this.inql.focusTab(this)
    }
}
