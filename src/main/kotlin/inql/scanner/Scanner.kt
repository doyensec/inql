package inql.scanner

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import inql.InQL
import inql.Logger
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.ui.EditableTabTitle
import inql.ui.EditableTabbedPane
import java.net.URI
import java.net.URISyntaxException
import javax.swing.BorderFactory

class Scanner(val inql: InQL) : EditableTabbedPane(), SavesAndLoadData {
    private val tabFactory = ScannerTabFactory(this)
    public val introspectionCache = IntrospectionCache(this.inql)

    companion object {
        fun fetchHeadersForHost(
            host: String,
            pathFilter: String? = null,
            headersFilter: Map<String, String>? = null,
        ): Map<String, String>? {
            val reqList = Burp.Montoya.proxy().history {
                val reqUrl: URI
                try {
                    reqUrl = URI.create(it.finalRequest().url())
                } catch (_: URISyntaxException) {
                    return@history false
                }
                if (host.lowercase() != reqUrl.host) return@history false
                if (pathFilter != null && pathFilter.lowercase() != reqUrl.path.lowercase()) return@history false
                if (headersFilter != null) {
                    // "AND" matching for headers
                    for (reqHeader in it.finalRequest().headers()) {
                        if (headersFilter.containsKey(reqHeader.name()) && reqHeader.value()
                                .contains(headersFilter[reqHeader.name()] as String)
                        ) {
                            return@history false
                        }
                    }
                }
                return@history true
            }
            if (reqList.isEmpty()) {
                Logger.warning("No request found during headers fetching")
                return null
            }
            return reqList.last().finalRequest().headers().associate { it.name() to it.value() }
        }
    }

    init {
        this.border = BorderFactory.createEmptyBorder(5, 0, 0, 0)
        this.setTabComponentFactory(this.tabFactory)
        this.addTitleChangeListener { this.tabTitleChangeListener(it) }
        this.newTab()
    }

    override fun closeTab(idx: Int) {
        val tab = this.tabbedPane.getComponentAt(idx) as ScannerTab
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
        // Add profile name
        if (scannerTab.linkedProfile != null) {
            val suffix = " [${scannerTab.linkedProfile!!.name}]"
            if (!title.endsWith(suffix)) title = "${title}$suffix"
        }
        e.text = title

        // Update saved data if needed
        if (scannerTab.scanResults.isNotEmpty()) {
            scannerTab.saveToProjectFileAsync()
            // No need to update the Scanner's tab list as the ID doesn't change
        }
    }

    fun newTabFromRequest(req: HttpRequest) {
        val tab = this.newTab() as ScannerTab
        tab.url = req.url()
        tab.requestTemplate = req.withBody("")
        this.inql.focusTab(this.inql.scanner)
    }

    fun getScannerTabs(): List<ScannerTab> {
        return this.tabs.filterIsInstance<ScannerTab>().toList()
    }

    override val saveStateKey: String
        get() = "Scanner"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject> {
        return this.getScannerTabs().filter { it.scanResults.isNotEmpty() } // Only save tabs that have results
    }

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setInteger("tabFactoryIdx", this.tabFactory.tabIdx)
        val tabs = this.getChildrenObjectsToSave()
        obj.setStringList("tabs", getSaveStateKeys(tabs))
        Logger.debug("Saving ${tabs.size} tab(s) to project file")
        return obj
    }

    override fun burpDeserialize(obj: PersistedObject) {
        val prevTabCnt = this.tabCount
        this.tabFactory.tabIdx = obj.getInteger("tabFactoryIdx")
        val tabIdList = obj.getStringList("tabs")
        if (tabIdList != null) {
            // Remove pre-existing tabs
            for (tab in 0..<prevTabCnt) {
                this.tabbedPane.removeTabAt(tab)
            }

            Logger.debug("Loading ${tabIdList.size} tab(s) from project file")

            for (tabId in tabIdList) {
                val id = tabId.substring(tabId.lastIndexOf('.') + 1).toInt()
                Logger.debug("Loading tab with id: $id")
                val tab = ScannerTab(this, id)
                if (!tab.loadFromProjectFile()) continue
                this.addTab(tab.getTabTitle(), tab)
                tab.setTabTitle(tab.getTabTitle())
            }
        }

        // Update Introspection Cache
        this.introspectionCache.populateFromScanner()
    }
}
