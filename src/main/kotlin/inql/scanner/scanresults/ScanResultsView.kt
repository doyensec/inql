package inql.scanner.scanresults

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.Logger
import inql.graphql.IGQLSchema
import inql.scanner.ScanResult
import inql.scanner.ScannerTab
import inql.ui.BorderPanel
import inql.ui.SendFromInqlHandler
import javax.swing.JSplitPane
import javax.swing.tree.DefaultMutableTreeNode

class ScanResultsView(val scannerTab: ScannerTab) : BorderPanel(0) {
    private val treeView = ScanResultsTreeView(this)
    private val payloadView = ScanResultsContentView(this)
    private var httpRequest: HttpRequest? = null
    private val sendToHandler = ScannerResultSendFromInqlHandler(this).also { it.setEnabled(false) }

    init {
        this.initUI()
        this.payloadView.setContextMenuHandler(sendToHandler)
        this.sendToHandler.addKeyboardShortcutHandler(this)
        this.sendToHandler.addKeyboardShortcutHandler(treeView)
    }

    private fun initUI() {
        val splitPane = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            this.treeView,
            this.payloadView
        )

        splitPane.isOneTouchExpandable = true
        splitPane.rightComponent.isVisible = true
        splitPane.setDividerLocation(0.5)
        splitPane.resizeWeight = 0.4

        this.add(splitPane)
    }

    fun refresh() {
        this.treeView.refresh()
    }

    private fun getNodeScanResult(node: DefaultMutableTreeNode): ScanResult? {
        var n = node
        while (n.userObject !is ScanResult && n.parent is DefaultMutableTreeNode) n = n.parent as DefaultMutableTreeNode
        if (n.userObject !is ScanResult) return null
        return n.userObject as ScanResult
    }

    private fun generateRequestForSelectedNode(node: DefaultMutableTreeNode): Boolean {
        val gqlElement = node.userObject
        if (gqlElement !is IGQLSchema.IGQLElement ||
            (gqlElement.type() != IGQLSchema.GQLElementType.MUTATION && gqlElement.type() != IGQLSchema.GQLElementType.QUERY)
        ) {
            this.httpRequest = null
            return false
        }

        // Find corresponding scanResult
        val scanResult = this.getNodeScanResult(node) ?: return false
        val requestTemplate = scanResult.requestTemplate
        val reqData = JsonObject()
        reqData.addProperty("query", gqlElement.content())
        this.httpRequest = requestTemplate
            .withService(HttpService.httpService(scanResult.requestTemplate.url()))
            .withBody(Gson().toJson(reqData))
        return true
    }

    fun selectionChangeListener(node: DefaultMutableTreeNode) {
        when (val content = node.userObject) {
            is String -> this.payloadView.load(content)
            is IGQLSchema.IGQLElement -> {
                this.payloadView.load(content)
            }

            else -> Logger.error("Unknown node type selected! ${content.javaClass.name}")
        }
        val requestGenerationSuccessful = this.generateRequestForSelectedNode(node)
        this.sendToHandler.setEnabled(requestGenerationSuccessful)
    }

    fun getCurrentRequest(): HttpRequest? {
        return this.httpRequest
    }

    class ScannerResultSendFromInqlHandler(val view: ScanResultsView) :
        SendFromInqlHandler(view.scannerTab.inql, false) {
        override fun getRequest(): HttpRequest? {
            return view.getCurrentRequest()
        }
    }
}