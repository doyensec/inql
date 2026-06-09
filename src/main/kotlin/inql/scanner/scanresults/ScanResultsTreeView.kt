package inql.scanner.scanresults

import inql.Logger
import inql.ui.BorderPanel
import java.awt.BorderLayout
import java.awt.event.HierarchyEvent
import javax.swing.JScrollPane
import javax.swing.JTree
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.event.TreeExpansionEvent
import javax.swing.event.TreeSelectionEvent
import javax.swing.event.TreeSelectionListener
import javax.swing.event.TreeWillExpandListener
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreePath
import javax.swing.tree.TreeSelectionModel

class ScanResultsTreeView(val view: ScanResultsView) : BorderPanel(), TreeSelectionListener {

    private val tree: JTree

    private var root: DefaultMutableTreeNode
    private var wantsDefaultExpansion = true
    private var applyingDefaultExpansion = false
    private var pendingSelectedPath: List<String>? = null

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
            it.showsRootHandles = true
            it.cellRenderer = ScanResultsTreeCellRenderer()
            it.addTreeSelectionListener(this)
            it.selectionModel.selectionMode = TreeSelectionModel.SINGLE_TREE_SELECTION
            it.expandsSelectedPaths = true
        }

        this.tree.addTreeWillExpandListener(object : TreeWillExpandListener {
            override fun treeWillExpand(event: TreeExpansionEvent) {
                val node = event.path.lastPathComponent
                if (node is LazyTreeNodeWithCustomLabel) {
                    node.ensureLoaded(tree.model as DefaultTreeModel)
                }
            }

            override fun treeWillCollapse(event: TreeExpansionEvent) {
                if (!applyingDefaultExpansion) {
                    wantsDefaultExpansion = false
                }
            }
        })

        tree.addTreeSelectionListener { e ->
            val node = e.path.lastPathComponent
            if (node is LazyLeafTreeNode) {
                node.ensureLoaded(tree.model as DefaultTreeModel)
                node.setSelectionRefreshCallback {
                    view.selectionChangeListener(node as DefaultMutableTreeNode)
                }
            }
            triggerCycleDetectionLoad(node)
        }

        this.root = DefaultMutableTreeNode("No results yet")
        this.tree.model = DefaultTreeModel(this.root)
        this.initUI()
        addHierarchyListener { e ->
            val changed = (e.changeFlags and HierarchyEvent.DISPLAYABILITY_CHANGED.toLong()) != 0L
            if (changed && isDisplayable) {
                scheduleApplyTreeState()
            }
        }
    }

    fun refresh() {
        val expandedPaths = if (wantsDefaultExpansion) emptySet() else captureExpandedPaths()
        if (expandedPaths.isNotEmpty()) {
            wantsDefaultExpansion = false
        }

        pendingSelectedPath = captureSelectedPath()

        this.root.userObject = this.view.scannerTab.host
        this.root.removeAllChildren()
        for (result in this.view.scannerTab.scanResults) {
            this.root.add(ScanResultTreeNode(result))
        }
        val model = tree.model as DefaultTreeModel
        model.nodeStructureChanged(root)

        scheduleApplyTreeState(expandedPaths)
    }

    fun ensureDefaultTreeExpansion() {
        if (!wantsDefaultExpansion || root.childCount == 0) return
        scheduleApplyTreeState()
    }

    fun repairTreeDisplay() {
        if (!isDisplayable || root.childCount == 0) return
        scheduleApplyTreeState()
    }

    private fun scheduleApplyTreeState(savedExpansion: Set<List<String>>? = null) {
        SwingUtilities.invokeLater {
            applyTreeState(savedExpansion ?: if (wantsDefaultExpansion) emptySet() else captureExpandedPaths())
        }
    }

    private fun applyTreeState(savedExpansion: Set<List<String>>, retry: Int = 0) {
        if (root.childCount == 0) return

        if (!isDisplayable) {
            if (retry < 10) {
                SwingUtilities.invokeLater { applyTreeState(savedExpansion, retry + 1) }
            }
            return
        }

        val model = tree.model as DefaultTreeModel

        if (wantsDefaultExpansion) {
            expandScanResultNodes()
            if (scanResultNodesAreExpanded()) {
                wantsDefaultExpansion = false
            }
        } else if (savedExpansion.isNotEmpty()) {
            restoreExpandedPaths(savedExpansion, model)
        }

        pendingSelectedPath?.let { selectedPath ->
            restoreSelection(selectedPath, model)
            pendingSelectedPath = null
        }

        refreshDisclosureHandles(model)
        tree.revalidate()
        tree.repaint()

        if (wantsDefaultExpansion && !scanResultNodesAreExpanded() && retry < 10) {
            SwingUtilities.invokeLater { applyTreeState(savedExpansion, retry + 1) }
        } else {
            scheduleDisclosureHandleRefresh(model)
        }
    }

    private fun scheduleDisclosureHandleRefresh(model: DefaultTreeModel) {
        SwingUtilities.invokeLater {
            if (!isDisplayable) return@invokeLater
            refreshDisclosureHandles(model)
            SwingUtilities.invokeLater {
                if (!isDisplayable) return@invokeLater
                tree.repaint()
            }
        }
    }

    private fun refreshDisclosureHandles(model: DefaultTreeModel) {
        for (i in 0 until root.childCount) {
            refreshDirectoryNodes(root.getChildAt(i) as DefaultMutableTreeNode, model)
        }
        tree.invalidate()
        tree.revalidate()
        tree.repaint()
    }

    private fun refreshDirectoryNodes(node: DefaultMutableTreeNode, model: DefaultTreeModel) {
        if (!node.isLeaf) {
            model.nodeChanged(node)
        }
        for (i in 0 until node.childCount) {
            refreshDirectoryNodes(node.getChildAt(i) as DefaultMutableTreeNode, model)
        }
    }

    private fun scanResultNodesAreExpanded(): Boolean {
        if (root.childCount == 0) return false
        for (i in 0 until root.childCount) {
            val child = root.getChildAt(i) as DefaultMutableTreeNode
            if (child.isLeaf) return false
            if (!tree.isExpanded(TreePath(child.path))) return false
        }
        return true
    }

    private fun nodeLabel(node: Any): String {
        return when (node) {
            is TreeNodeWithCustomLabel -> node.label
            is DefaultMutableTreeNode -> node.toString()
            else -> node.toString()
        }
    }

    private fun pathToLabels(path: TreePath): List<String> {
        return path.path.map { nodeLabel(it) }.drop(1)
    }

    private fun captureExpandedPaths(): Set<List<String>> {
        val expanded = linkedSetOf<List<String>>()
        val enumeration = tree.getExpandedDescendants(TreePath(root)) ?: return expanded
        while (enumeration.hasMoreElements()) {
            val labels = pathToLabels(enumeration.nextElement())
            if (labels.isNotEmpty()) expanded.add(labels)
        }
        return expanded
    }

    private fun captureSelectedPath(): List<String>? {
        val path = tree.selectionPath ?: return null
        val labels = pathToLabels(path)
        return labels.ifEmpty { null }
    }

    private fun findNodeByLabels(labels: List<String>): DefaultMutableTreeNode? {
        var current: DefaultMutableTreeNode = root
        for (label in labels) {
            var found: DefaultMutableTreeNode? = null
            for (i in 0 until current.childCount) {
                val child = current.getChildAt(i) as DefaultMutableTreeNode
                if (nodeLabel(child) == label) {
                    found = child
                    break
                }
            }
            if (found == null) return null
            current = found
        }
        return current
    }

    private fun restoreExpandedPaths(expandedPaths: Set<List<String>>, model: DefaultTreeModel) {
        for (labels in expandedPaths) {
            val node = findNodeByLabels(labels) ?: continue
            tree.expandPath(TreePath(node.path))
            if (node is LazyTreeNodeWithCustomLabel) {
                node.ensureLoaded(model)
            }
        }
        refreshDisclosureHandles(model)
    }

    private fun triggerCycleDetectionLoad(node: Any) {
        if (node !is DefaultMutableTreeNode) return
        val entry = node.userObject as? CycleDetectionEntry ?: return
        entry.ensureLoaded {
            view.selectionChangeListener(node)
        }
    }

    private fun expandScanResultNodes() {
        applyingDefaultExpansion = true
        try {
            for (i in 0 until root.childCount) {
                val scanResultNode = root.getChildAt(i) as DefaultMutableTreeNode
                val path = TreePath(scanResultNode.path)
                tree.expandPath(path)
                tree.makeVisible(path)
            }
            for (row in 0 until root.childCount) {
                tree.expandRow(row)
            }
            refreshDisclosureHandles(tree.model as DefaultTreeModel)
        } finally {
            applyingDefaultExpansion = false
        }
    }

    private fun restoreSelection(selectedPath: List<String>?, model: DefaultTreeModel) {
        if (selectedPath == null) return
        val node = findNodeByLabels(selectedPath) ?: return
        tree.selectionPath = TreePath(node.path)
        when (node) {
            is LazyLeafTreeNode -> {
                node.ensureLoaded(model)
                node.setSelectionRefreshCallback {
                    view.selectionChangeListener(node)
                }
            }
            else -> {
                triggerCycleDetectionLoad(node)
                if (node.isLeaf) view.selectionChangeListener(node)
            }
        }
    }

    override fun valueChanged(e: TreeSelectionEvent) {
        try {
            this.tree.repaint()
        } catch (e: Exception) {
            Logger.warning("Caught exception while repainting tree")
        }
        val node = (this.tree.lastSelectedPathComponent ?: return) as DefaultMutableTreeNode
        if (!node.isLeaf) return
        this.view.selectionChangeListener(node)
    }
}
