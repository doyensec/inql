package inql.scanner.scanresults

import inql.scanner.ScanResult
import java.awt.Component
import java.awt.Graphics
import javax.swing.Icon
import javax.swing.JTree
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeCellRenderer
import javax.swing.tree.TreePath

/**
 * Aligns all direct children of a scan result row (Queries, Request Template, etc.)
 * so labels start at the same horizontal position. Leaf rows use a transparent
 * icon sized to match folder icons; folder rows keep the default open/close icons.
 */
class ScanResultsTreeCellRenderer : DefaultTreeCellRenderer() {
    override fun getTreeCellRendererComponent(
        tree: JTree,
        value: Any?,
        selected: Boolean,
        expanded: Boolean,
        leaf: Boolean,
        row: Int,
        hasFocus: Boolean,
    ): Component {
        super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus)

        val path = if (row >= 0) tree.getPathForRow(row) else null
        if (path == null || !isScanResultSectionRow(path)) {
            return this
        }

        if (leaf) {
            icon = transparentIcon(matchingIconWidth(), matchingIconHeight())
            disabledIcon = icon
        }

        return this
    }

    private fun isScanResultSectionRow(path: TreePath): Boolean {
        val parent = path.parentPath?.lastPathComponent as? DefaultMutableTreeNode ?: return false
        return parent.userObject is ScanResult
    }

    private fun matchingIconWidth(): Int {
        return maxOf(closedIcon?.iconWidth ?: 0, openIcon?.iconWidth ?: 0, 16)
    }

    private fun matchingIconHeight(): Int {
        return maxOf(closedIcon?.iconHeight ?: 0, openIcon?.iconHeight ?: 0, 16)
    }

    private fun transparentIcon(width: Int, height: Int): Icon {
        return TransparentIcon(width, height)
    }

    private class TransparentIcon(
        private val width: Int,
        private val height: Int,
    ) : Icon {
        override fun getIconWidth(): Int = width
        override fun getIconHeight(): Int = height
        override fun paintIcon(c: Component?, g: Graphics?, x: Int, y: Int) {}
    }
}
