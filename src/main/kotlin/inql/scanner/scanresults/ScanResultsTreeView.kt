package inql.scanner.scanresults

import inql.ui.BorderPanel
import java.awt.BorderLayout
import javax.swing.JScrollPane
import javax.swing.JTree
import javax.swing.UIManager
import javax.swing.event.TreeSelectionEvent
import javax.swing.event.TreeSelectionListener
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeSelectionModel

class ScanResultsTreeView(val view: ScanResultsView) : BorderPanel(), TreeSelectionListener {

    private val tree: JTree

    private var root: DefaultMutableTreeNode
    private fun setupLookAndFeel() {
        UIManager.put("Tree.showDefaultIcons", true)
        UIManager.put("Tree.paintLines", true)
        UIManager.put("Tree.lineTypeDashed", true)
        UIManager.put("Tree.showsRootHandles", true)
        UIManager.put("Tree.rendererFillBackground", false)
    }

    private fun initUI() {
        val nestedPanel = BorderPanel()
        nestedPanel.add(BorderLayout.CENTER, this.tree)
        val scrollPane = JScrollPane()
        scrollPane.viewport.add(nestedPanel)
        this.add(BorderLayout.CENTER, scrollPane)
    }

    init {
        this.setupLookAndFeel()
        this.tree = JTree(DefaultMutableTreeNode()).also {
            it.isRootVisible = false
            it.addTreeSelectionListener(this)
            it.selectionModel.selectionMode = TreeSelectionModel.SINGLE_TREE_SELECTION
            it.expandsSelectedPaths = true
        }
        this.root = DefaultMutableTreeNode("No results yet")
        this.tree.model = DefaultTreeModel(this.root)
        this.initUI()
    }

    fun refresh() {
        this.root.userObject = this.view.scannerTab.host
        this.root.removeAllChildren()
        for (result in this.view.scannerTab.scanResults) {
            this.root.add(ScanResultTreeNode(result))
        }
        this.tree.model = DefaultTreeModel(this.root)
        for (i in 0 until this.tree.rowCount) {
            this.tree.expandRow(i)
        }
    }

    override fun valueChanged(e: TreeSelectionEvent) {
        this.tree.repaint() // For some reason, sometimes the UI doesn't update
        val node = (this.tree.lastSelectedPathComponent ?: return) as DefaultMutableTreeNode
        if (!node.isLeaf) return // We don't care about folders
        this.view.selectionChangeListener(node)
    }
}
