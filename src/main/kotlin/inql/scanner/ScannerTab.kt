package inql.scanner

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import inql.scanner.scanconfig.ScanConfigView
import inql.scanner.scanresults.ScanResultsView
import inql.ui.EditableTab
import inql.ui.ErrorDialog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.awt.CardLayout
import java.io.File
import java.net.URI
import java.net.URISyntaxException
import javax.swing.JPanel
import inql.session.Session

class ScannerTab(val scanner: Scanner, val id: Int) : JPanel(CardLayout()) {
    companion object {
        const val SCAN_CONFIG_VIEW = "SCAN_CONFIG_VIEW"
        const val SCAN_RESULT_VIEW = "SCAN_RESULT_VIEW"
    }

    var session: Session? = null
    var sessionConfig: String
        get() = this.scanConfigView.sessionYaml
        set(s) {
            this.scanConfigView.sessionYaml = s
        }
    private var _tabTitle = "ScannerTab"
    val inql = scanner.inql
    private val scanConfigView = ScanConfigView(this)
    private val scanResultsView = ScanResultsView(this)

    var url: String
        get() = this.scanConfigView.url ?: ""
        set(s) {
            this.scanConfigView.url = s
        }
    var fileSchema: String
        get() = this.scanConfigView.file ?: ""
        set(s) {
            this.scanConfigView.file = s
        }

    val host: String?
        get() {
            return try {
                URI.create(this.url).host
            } catch (_: URISyntaxException) {
                null
            }
        }

    // Gets triggered from Scanner.newTabFromRequest when creating a new tab from an existing HTTP request
    fun updateFromHttpRequest(req: HttpRequest) {
        this.url = req.url()

        sessionConfig = Session.updateTemplateWithUrl(sessionConfig, req.url())
        sessionConfig = Session.updateTemplateWithHeaders(sessionConfig, req.headers())
    }

    private fun showView(card: String) {
        if (!setOf<String>(
                SCAN_CONFIG_VIEW,
                SCAN_RESULT_VIEW,
            ).contains(card)
        ) {
            throw Exception("Card ID not recognized: $card")
        }
        (this.layout as CardLayout).show(this, card)
    }

    fun showResultsView() {
        this.showView(SCAN_RESULT_VIEW)
    }

    fun showConfigView() {
        this.showView(SCAN_CONFIG_VIEW)
    }

    init {
        // initialize new page view and scanner view
        this.add(scanConfigView, SCAN_CONFIG_VIEW)
        this.add(scanResultsView, SCAN_RESULT_VIEW)
        this.showView(SCAN_CONFIG_VIEW)

        Burp.Montoya.userInterface().applyThemeToComponent(scanConfigView)
        Burp.Montoya.userInterface().applyThemeToComponent(scanResultsView)

        sessionConfig = Session.createEmptyTemplate()
    }

    fun launchScan() {
        CoroutineScope(Dispatchers.IO).launch {
            this@ScannerTab.analyze()
        }
    }

    private suspend fun analyze() {
        if (this.fileSchema.isNotBlank()) {
            if (!File(this.fileSchema).exists()) {
                scanFailed("File not found")
                return
            }
            try {
                val fileContent = File(this.fileSchema).readText()
                try {
                    this.session = Session.createWithLocalSchema(this, fileContent)
                } catch (e: Exception) {
                    scanFailed("Could not initiate local scan: ${e.message}")
                    return
                }
            } catch (e: Exception) {
                scanFailed("Could not read file")
                return
            }
        } else {
            try {
                this.session = Session.createWithRemoteSchema(this)
            } catch (e: Exception) {
                scanFailed("Could not initiate remote scan: ${e.message}")
                return
            }
        }

        try {
            this.session!!.analyze()
        } catch (e: Exception) {
            scanFailed("Schema analysis failed: ${e.message}")
            return
        }

        this.scanCompleted()
    }

    private suspend fun scanCompleted() {
        this.scanConfigView.setBusy(false) // Do we need this?
        this.showView(SCAN_RESULT_VIEW)
        this.scanResultsView.refresh(this.session!!)
    }

    private fun scanFailed(reason: String?) {
        if (!reason.isNullOrBlank()) ErrorDialog("Scan failed: $reason")
        this.scanConfigView.setBusy(false)
    }

    fun getTabTitle(): String {
        val idx = this.scanner.tabbedPane.indexOfComponent(this)
        if (idx == -1) return this._tabTitle
        val tab = this.scanner.tabbedPane.getTabComponentAt(idx) as EditableTab
        val title = tab.tabTitle
        return title.text
    }

    fun setTabTitle(text: String) {
        this._tabTitle = text
        val idx = this.scanner.tabbedPane.indexOfComponent(this)
        if (idx == -1) return
        val tab = this.scanner.tabbedPane.getTabComponentAt(idx) as EditableTab
        val title = tab.tabTitle
        title.text = text
    }

    fun onClose() {
        // FIXME: Figure out how to properly delete references to this tab when it's closed
        //if (this.scanResults.isNotEmpty()) this.scanner.deleteChildObjectAsync(this)
    }
}
