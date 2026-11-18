package inql.ui

import inql.Logger
import java.awt.Desktop
import java.net.URI
import javax.swing.JEditorPane
import javax.swing.JScrollPane
import javax.swing.JViewport
import javax.swing.ScrollPaneConstants
import javax.swing.SwingUtilities
import javax.swing.event.HyperlinkEvent

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

    fun attachHyperlinkHandler(pane: JEditorPane) {
        pane.addHyperlinkListener { e ->
            if (e.eventType != HyperlinkEvent.EventType.ACTIVATED) return@addHyperlinkListener
            val uri = e.url?.toURI() ?: e.description?.let { URI(it) } ?: return@addHyperlinkListener
            try {
                Desktop.getDesktop().browse(uri)
            } catch (ex: Exception) {
                Logger.error("Failed to open link: ${ex.message}")
            }
        }
    }

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
