package inql.ui

import burp.Burp
import inql.attackvector.ScanResultsTable
import inql.attackvector.TestStatus
import java.awt.Color
import javax.swing.JEditorPane
import javax.swing.SwingUtilities
import javax.swing.UIManager

/**
 * Theme-aware HTML documents for read-only [JEditorPane]s (Swing renders HTML 3.2 with a CSS subset).
 *
 * Bodies only reference the CSS classes below and never hard-code colors. [show] swaps in the style sheet
 * of the current theme, and shows the document again when the pane is re-themed, so HTML rendered in one
 * theme (e.g. scan results) is displayed correctly in the other.
 *
 * Font sizes use pt: Swing scales CSS px by ~1.33, while pt matches Java font sizes.
 */
object HtmlDocument {
    private const val HTML_PROPERTY = "inql.html"
    private val STYLE_BLOCK = Regex("<style>.*?</style>", RegexOption.DOT_MATCHES_ALL)

    /** Base font size in pt, one step above Burp's table font so reports read comfortably. */
    fun baseFontSize(): Int = (uiFont()?.size ?: 13) + 1

    fun wrap(body: String): String = "<html><head>${styleBlock()}</head><body>$body</body></html>"

    fun show(pane: JEditorPane, html: String) {
        if (pane.getClientProperty(HTML_PROPERTY) == null) {
            // Burp updates the UI of every component when switching between light and dark mode.
            pane.addPropertyChangeListener("UI") {
                val current = pane.getClientProperty(HTML_PROPERTY) as? String ?: return@addPropertyChangeListener
                SwingUtilities.invokeLater { show(pane, current) }
            }
        }
        pane.putClientProperty(HTML_PROPERTY, html)
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, false)
        pane.contentType = "text/html"
        pane.isEditable = false
        pane.text = STYLE_BLOCK.replaceFirst(html, Regex.escapeReplacement(styleBlock()))
        pane.caretPosition = 0
        HtmlScrollPane.refreshContentSize(pane)
    }

    /** Class of the colored status text for [TestStatus] values, e.g. in scan result details. */
    fun statusClass(status: TestStatus): String = "status-${status.name.lowercase()}"

    fun css(color: Color): String = "rgb(${color.red},${color.green},${color.blue})"

    fun linkColor(): Color = if (Burp.isDarkMode()) Color(100, 181, 246) else Color(0, 102, 204)

    private fun styleBlock(): String {
        val dark = Burp.isDarkMode()
        val text = css(ScanResultsTable.primaryTextColor())
        val muted = css(ScanResultsTable.mutedTextColor())
        val border = css(ScanResultsTable.borderColor())
        val family = uiFont()?.family ?: "sans-serif"
        val size = baseFontSize()
        val statusRules = TestStatus.entries.joinToString("\n") {
            ".${statusClass(it)} { color: ${css(ScanResultsTable.statusColor(it))}; }"
        }
        return """
            <style>
              body { font-family: $family; font-size: ${size}pt; color: $text; margin: 6px; }
              h1 { font-size: ${size + 6}pt; font-weight: bold; margin: 0; }
              h2 { font-size: ${size + 2}pt; font-weight: bold; margin: 12px 0 4px 0; }
              h3 { font-size: ${size}pt; font-weight: bold; margin: 8px 0 2px 0; }
              p { margin: 2px 0 2px 0; }
              b { font-weight: bold; }
              a { color: ${css(linkColor())}; text-decoration: none; }
              ul { margin-left: 20px; }
              th { text-align: left; font-weight: bold; color: $muted; }
              th, td { font-size: ${size}pt; text-align: left; vertical-align: top; }
              .muted { color: $muted; }
              .small { font-size: ${size - 1}pt; }
              .grid { border: 1px solid $border; }
              .row-even { background-color: ${css(ScanResultsTable.rowBackground(0))}; }
              .row-odd { background-color: ${css(ScanResultsTable.rowBackground(1))}; }
              .risk-exposed { color: ${css(if (dark) Color(239, 83, 80) else Color(198, 40, 40))}; }
              .risk-safe { color: ${css(if (dark) Color(102, 187, 106) else Color(46, 125, 50))}; }
              .risk-unknown { color: $muted; }
              $statusRules
            </style>
        """.trimIndent()
    }

    /** Same font as the Attack Vector scanner's results table. */
    private fun uiFont() = UIManager.getFont("Table.font") ?: UIManager.getFont("Label.font")
}
