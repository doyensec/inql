package inql.scanner.scanresults

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.Config
import inql.Logger
import inql.graphql.formatting.Formatter
import inql.scanner.ScanResult
import inql.scanner.ScannerTab
import inql.ui.BorderPanel
import inql.ui.SendFromInqlHandler
import inql.utils.QueryToRequestConverter
import javax.swing.JSplitPane
import javax.swing.tree.DefaultMutableTreeNode

class ScanResultsView(val scannerTab: ScannerTab) : BorderPanel(0) {
    private val treeView = ScanResultsTreeView(this)
    private val payloadView = ScanResultsContentView(this)
    private var currentNode: DefaultMutableTreeNode? = null
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
            this.payloadView,
        )

        splitPane.isOneTouchExpandable = true
        splitPane.rightComponent.isVisible = true
        splitPane.setDividerLocation(0.5)
        splitPane.resizeWeight = 0.2

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

    private fun generateRequest(requestTemplate: HttpRequest, query: String): HttpRequest? {
        // Find corresponding scanResult
        val reqData = JsonObject()
        reqData.addProperty("query", query)
        return requestTemplate
            .withService(HttpService.httpService(requestTemplate.url()))
            .withBody(query)
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
            is ScanResultElement -> {
                // If it's something else, (PoI, Cycle detection), don't
                this.payloadView.load(content.content())
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            else -> Logger.error("Unknown node type selected! ${content.javaClass.name}")
        }
    }

    class ScannerResultSendFromInqlHandler(val view: ScanResultsView) :
        SendFromInqlHandler(view.scannerTab.inql, false) {
        private val shouldStripComments = Config.getInstance().getBoolean("editor.send_to.strip_comments")

        override fun getRequest(): HttpRequest? {
            Logger.warning("VALUE: $shouldStripComments")

            val converter = QueryToRequestConverter(view.scannerTab.scanResults.last())
            val query = converter.convert(view.currentNode.toString(), view.currentNode?.parent.toString(), Config.getInstance().getInt("codegen.depth")!!)

            val node = view.currentNode ?: return null
            val requestTemplate = view.getNodeScanResult(node)?.requestTemplate ?: return null

            return view.generateRequest(requestTemplate, query)
        }

        override fun getText(): String {
            return view.payloadView.getText()
        }
    }
}
