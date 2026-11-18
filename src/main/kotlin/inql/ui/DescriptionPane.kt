package inql.ui

import inql.attackvector.ScanResultsTable
import java.awt.Dimension
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.StringReader
import javax.swing.JEditorPane
import javax.swing.JSplitPane
import javax.swing.JViewport
import javax.swing.SwingUtilities
import javax.swing.plaf.basic.BasicSplitPaneUI
import javax.swing.text.html.HTMLDocument

/**
 * Read-only HTML description shown at the top of a tab. Its preferred height fits the whole text
 * wrapped at the current width, so it is never cut off by default. Text and link colors follow the Burp theme.
 */
class DescriptionPane(html: String) : JEditorPane() {
    /** Called when the width (and so the height needed to fit the text) changes. */
    var onWidthChanged: (() -> Unit)? = null
    private var measuredWidth = -1
    private lateinit var html: String

    /**
     * Off-screen editor sharing the document, used only to measure the text height. Laying out the displayed
     * views from getPreferredSize() makes them request another layout, which loops forever on the EDT.
     */
    private val measurer = JEditorPane().apply {
        contentType = "text/html"
        isEditable = false
        border = null
    }
    private var cachedContentWidth = -1
    private var cachedContentHeight = 0

    init {
        contentType = "text/html"
        isEditable = false
        this.html = html
        loadDocument()
        HtmlScrollPane.attachHyperlinkHandler(this)
        addComponentListener(object : ComponentAdapter() {
            override fun componentResized(e: ComponentEvent?) {
                if (width == measuredWidth) return
                measuredWidth = width
                revalidate()
                onWidthChanged?.invoke()
            }
        })
    }

    /** Called by Swing whenever the theme changes, e.g. when switching between Burp's light and dark mode. */
    override fun updateUI() {
        super.updateUI()
        // Also runs from the JEditorPane constructor, before the text is set.
        if (this::html.isInitialized) loadDocument()
    }

    /**
     * Loads the text into a new document with text and link colors for the current theme (the default style sheet
     * hard-codes dark text). Rules are added before the views exist: changing the style sheet of a displayed
     * document right after updateUI() leaves its views without a font.
     */
    private fun loadDocument() {
        val doc = editorKit.createDefaultDocument() as HTMLDocument
        // Bottom margin mirrors the default top margin of the <h2> heading.
        doc.styleSheet.addRule("body { color: ${HtmlDocument.css(ScanResultsTable.primaryTextColor())}; margin-bottom: 10px; }")
        doc.styleSheet.addRule("a { color: ${HtmlDocument.css(HtmlDocument.linkColor())}; }")
        editorKit.read(StringReader(html), doc, 0)
        document = doc
        measurer.document = doc
        cachedContentWidth = -1
    }

    override fun getPreferredSize(): Dimension {
        val availableWidth = (parent as? JViewport)?.width ?: width
        if (availableWidth <= 0) return Dimension(0, super.getPreferredSize().height)
        val contentWidth = availableWidth - insets.left - insets.right
        if (contentWidth != cachedContentWidth) {
            measurer.setSize(contentWidth, Short.MAX_VALUE.toInt())
            cachedContentHeight = measurer.preferredSize.height
            cachedContentWidth = contentWidth
        }
        return Dimension(0, cachedContentHeight + insets.top + insets.bottom)
    }
}

/**
 * Keeps the divider of a vertical split right below the top component's preferred height, so the
 * [description] is fully visible. Stops adjusting once the user drags the divider.
 */
fun JSplitPane.fitTopComponent(description: DescriptionPane) {
    resizeWeight = 0.0
    var userMoved = false
    val dragListener = object : MouseAdapter() {
        override fun mousePressed(e: MouseEvent?) {
            userMoved = true
        }
    }
    val attach = { (ui as? BasicSplitPaneUI)?.divider?.addMouseListener(dragListener) }
    attach()
    // Theming (e.g. Burp's applyThemeToComponent) replaces the UI and with it the divider.
    addPropertyChangeListener("UI") { attach() }
    description.onWidthChanged = {
        SwingUtilities.invokeLater {
            if (!userMoved) dividerLocation = insets.top + topComponent.preferredSize.height
        }
    }
}
