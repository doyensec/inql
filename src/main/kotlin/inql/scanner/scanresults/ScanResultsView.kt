package inql.scanner.scanresults

import inql.scanner.ScannerTab
import inql.session.Session
import inql.ui.BorderPanel
import kotlinx.coroutines.runBlocking
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTree
import javax.swing.UIManager

/*
 * This class is responsible for displaying the results of a scan. It focuses on
 * managing overall layout and delegates the tree population logic to LazyTreeModel.
 * It also listens to node selection events and updates the right panel with the
 * selected node's details.
 */

class ScanResultsView(val scannerTab: ScannerTab): BorderPanel(0) {
    private val treeModel = ScanResultsTreeModel()
    val payloadView = ScanResultsContentView()
    private val treeView: JTree = JTree(treeModel).apply {
        UIManager.put("Tree.showDefaultIcons", true)
        UIManager.put("Tree.paintLines", true)
        UIManager.put("Tree.lineTypeDashed", true)
        UIManager.put("Tree.showsRootHandles", true)
        UIManager.put("Tree.rendererFillBackground", false)

        isRootVisible = false
        addTreeSelectionListener { e ->
            val selectedNode = e.path.lastPathComponent as? ScanResultsTreeNode
            selectedNode?.let { node ->
                if (node.isLeaf) {
                    runBlocking {
                        node.getContent()?.let { scanResult ->
                            payloadView.load(scanResult)
                            sendToHandler.setEnabled(scanResult is ScanResult.GraphQL)
                        }
                    }
                }
            }
        }
    }
    private val sendToHandler = ScannerResultsHandler(this).also {
        it.addKeyboardShortcutHandler(this)
        it.addKeyboardShortcutHandler(this.treeView)
        payloadView.setContextMenuHandler(it)
    }
    var session: Session? = null

    val selectedNode: ScanResultsTreeNode?
        get() = treeView.lastSelectedPathComponent as? ScanResultsTreeNode

    init {
        val splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(treeView), payloadView).apply {
            isOneTouchExpandable = true
            rightComponent.isVisible = true
            setDividerLocation(0.5)
            resizeWeight = 0.4
        }

        this.add(splitPane)
    }

    suspend fun refresh(session: Session) {
        this.session = session
        treeModel.refresh(session)

        // We did this previously, not sure if necessary:
        for (i in 0 until treeView.rowCount) {
            treeView.expandRow(i)
        }

        treeView.repaint()
    }
}