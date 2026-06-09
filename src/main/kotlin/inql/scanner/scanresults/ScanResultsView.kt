package inql.scanner.scanresults

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import inql.Config
import inql.Logger
import inql.scanner.ScanResult
import inql.scanner.ScannerTab
import inql.ui.BorderPanel
import inql.ui.SendFromInqlHandler
import java.lang.ref.WeakReference
import inql.utils.QueryToRequestConverter
import javax.swing.JSplitPane
import javax.swing.tree.DefaultMutableTreeNode

class ScanResultsView(val scannerTab: ScannerTab) : BorderPanel(0) {
    private val treeView = ScanResultsTreeView(this)
    private val payloadView = ScanResultsContentView(this)
    private var currentNode: DefaultMutableTreeNode? = null
    private val sendToHandler = ScannerResultSendFromInqlHandler(this).also { it.setEnabled(false) }

    companion object {
        private val instances = mutableListOf<WeakReference<ScanResultsView>>()
        fun getAllInstances(): List<ScanResultsView> {
            instances.removeIf { it.get() == null }
            return instances.mapNotNull { it.get() }
        }
    }

    init {
        this.initUI()
        instances.add(WeakReference(this))
        this.payloadView.setContextMenuHandler(sendToHandler)
        this.sendToHandler.addKeyboardShortcutHandler(this)
        this.sendToHandler.addKeyboardShortcutHandler(treeView)
    }

    private fun initUI() {
        addHierarchyListener { e ->
            val changed = (e.changeFlags and java.awt.event.HierarchyEvent.DISPLAYABILITY_CHANGED.toLong()) != 0L
            if (changed && !isDisplayable) {
                dispose()
            }
        }

        val splitPane = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            this.treeView,
            this.payloadView,
        )

        splitPane.isOneTouchExpandable = true
        splitPane.rightComponent.isVisible = true
        splitPane.setDividerLocation(0.5)
        splitPane.resizeWeight = 0.2

        this.add(splitPane)
    }

    fun dispose() {
        // Remove from our registry
        instances.removeIf { it.get() === this || it.get() == null }

        for (l in hierarchyListeners) removeHierarchyListener(l)
    }

    fun refresh() {
        this.treeView.refresh()
    }

    fun repairTreeDisplay() {
        this.treeView.repairTreeDisplay()
    }

    fun ensureDefaultTreeExpansion() {
        this.treeView.ensureDefaultTreeExpansion()
    }

    private fun getNodeScanResult(node: DefaultMutableTreeNode): ScanResult? {
        var n = node
        while (n.userObject !is ScanResult && n.parent is DefaultMutableTreeNode) n = n.parent as DefaultMutableTreeNode
        if (n.userObject !is ScanResult) return null
        return n.userObject as ScanResult
    }

    /**
     * Rebuilds [requestTemplate] with a new body (same URL/service as the captured scan request).
     */
    internal fun requestTemplateWithBody(requestTemplate: HttpRequest, body: String): HttpRequest {
        return requestTemplate
            .withService(HttpService.httpService(requestTemplate.url()))
            .withBody(body)
    }

    fun selectionChangeListener(node: DefaultMutableTreeNode) {
        when (val content = node.userObject) {
            is String -> {
                this.payloadView.load(content)
                this.sendToHandler.setEnabled(false)
            }
            is GQLQueryElement -> {
                // If it's a query/mutation/subscription, enable the handler
                this.payloadView.load(content)
                this.sendToHandler.setEnabled(true)
                this.currentNode = node
            }
            is CycleDetectionEntry -> {
                content.ensureLoaded { this.selectionChangeListener(node) }
                when (val payload = content.payload) {
                    CycleDetectionPayload.Loading -> this.payloadView.loadCycleLoading()
                    is CycleDetectionPayload.Ready -> this.payloadView.loadCycleResults(payload.scanResult, payload.cycles)
                }
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            is ScanResultElement -> {
                // If it's something else (e.g. PoI), show as text
                this.payloadView.load(content.content())
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            else -> Logger.error("Unknown node type selected! ${content.javaClass.name}")
        }
    }

    fun getPayloadText(): String = payloadView.getText()

    class ScannerResultSendFromInqlHandler(val view: ScanResultsView) :
        SendFromInqlHandler(view.scannerTab.inql, false) {

        override fun getRequest(): HttpRequest? {
            val node = view.currentNode ?: return null
            val scanResult = view.getNodeScanResult(node) ?: return null
            val converter = QueryToRequestConverter(scanResult)
            val query = converter.convert(node.toString(), node.parent.toString(), Config.getInstance().getInt("codegen.depth")!!)
            val requestTemplate = scanResult.requestTemplate

            return view.requestTemplateWithBody(requestTemplate, query)
        }

        override fun getText(): String {
            return view.getPayloadText()
        }
    }
}
