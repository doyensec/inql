package inql.scanner.scanresults

import inql.scanner.ScanResult
import javax.swing.event.TreeModelEvent
import javax.swing.event.TreeModelListener
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeModel
import javax.swing.tree.TreePath

object ScanResultsTreeMatcher {
    fun normalizeFilter(text: String): String = text.trim().lowercase()

    fun nodeMatches(node: DefaultMutableTreeNode, filter: String): Boolean {
        if (filter.isEmpty()) return true
        val needle = normalizeFilter(filter)

        when (val obj = node.userObject) {
            is GQLQueryElement -> return obj.matchesSearch(needle)
            is GQLTypeElement -> return obj.name.contains(needle, ignoreCase = true)
            is ScanResult -> return false
            else -> {
                val label = (node as? TreeNodeWithCustomLabel)?.label ?: node.toString()
                return label.contains(needle, ignoreCase = true)
            }
        }
    }

    fun hasMatchingDescendant(node: DefaultMutableTreeNode, filter: String): Boolean {
        if (filter.isEmpty()) return true
        for (i in 0 until node.childCount) {
            val child = node.getChildAt(i) as DefaultMutableTreeNode
            if (shouldShowNode(child, filter)) return true
        }
        return false
    }

    fun shouldShowNode(node: DefaultMutableTreeNode, filter: String): Boolean {
        if (filter.isEmpty()) return true
        if (nodeMatches(node, filter)) return true
        return hasMatchingDescendant(node, filter)
    }
}

class ScanResultsTreeFilterModel(
    val source: DefaultTreeModel,
) : TreeModel {

    private val listeners = mutableListOf<TreeModelListener>()

    var filter: String = ""
        set(value) {
            if (field == value) return
            field = value
            fireStructureChanged()
        }

    override fun getRoot(): Any = source.root

    override fun getChild(parent: Any, index: Int): Any {
        return visibleChildren(parent as DefaultMutableTreeNode)[index]
    }

    override fun getChildCount(parent: Any): Int {
        return visibleChildren(parent as DefaultMutableTreeNode).size
    }

    override fun isLeaf(node: Any): Boolean {
        val n = node as DefaultMutableTreeNode
        if (filter.isNotEmpty() && getChildCount(n) > 0) return false
        return n.isLeaf
    }

    override fun getIndexOfChild(parent: Any, child: Any): Int {
        return visibleChildren(parent as DefaultMutableTreeNode).indexOf(child)
    }

    override fun valueForPathChanged(path: TreePath, newValue: Any) {
        source.valueForPathChanged(path, newValue)
    }

    override fun addTreeModelListener(l: TreeModelListener) {
        listeners.add(l)
    }

    override fun removeTreeModelListener(l: TreeModelListener) {
        listeners.remove(l)
    }

    fun reloadFromSource() {
        fireStructureChanged()
    }

    private fun fireStructureChanged() {
        val root = source.root
        val event = TreeModelEvent(this, arrayOf(root), null, null)
        for (listener in listeners.toList()) {
            listener.treeStructureChanged(event)
        }
    }

    private fun visibleChildren(parent: DefaultMutableTreeNode): List<DefaultMutableTreeNode> {
        val children = (0 until source.getChildCount(parent)).map {
            source.getChild(parent, it) as DefaultMutableTreeNode
        }
        if (filter.isEmpty()) return children
        return children.filter { ScanResultsTreeMatcher.shouldShowNode(it, filter) }
    }
}
