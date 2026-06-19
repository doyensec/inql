package inql.ui

import javax.swing.JEditorPane
import javax.swing.JScrollPane
import javax.swing.JViewport
import javax.swing.ScrollPaneConstants
import javax.swing.SwingUtilities

object HtmlScrollPane {
    fun configure(scrollPane: JScrollPane) {
        scrollPane.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        scrollPane.verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        scrollPane.isWheelScrollingEnabled = true
        scrollPane.viewport.scrollMode = JViewport.SIMPLE_SCROLL_MODE
        scrollPane.verticalScrollBar.unitIncrement = 24
        scrollPane.horizontalScrollBar.unitIncrement = 24
        scrollPane.verticalScrollBar.blockIncrement = 120
        scrollPane.horizontalScrollBar.blockIncrement = 120
    }

    /**
     * JEditorPane HTML reflows to the viewport width by default. Measure at unbounded width
     * so wide tables and long lines can scroll horizontally.
     */
    fun refreshContentSize(pane: JEditorPane) {
        SwingUtilities.invokeLater {
            pane.setSize(Int.MAX_VALUE / 2, Int.MAX_VALUE / 2)
            val size = pane.preferredSize
            pane.setPreferredSize(size)
            pane.setSize(size)
            (pane.parent as? JViewport)?.revalidate()
        }
    }
}
