package inql.ui

import burp.Burp
import inql.graphql.formatting.Formatter
import inql.graphql.formatting.Style
import inql.utils.getTextAreaComponent
import org.apache.commons.text.StringEscapeUtils
import java.awt.Font
import javax.swing.JEditorPane
import javax.swing.text.StyleConstants
import javax.swing.text.html.HTMLDocument

class GraphQLEditor(readOnly: Boolean = false, val isIntrospection: Boolean = false) : JEditorPane("text/html", "") {
    companion object {
        fun stripHTML(content: String): String {
            return StringEscapeUtils.unescapeHtml4(content.replace(Regex("<([^>]+)>"), ""))
        }

        private fun getHTML(content: String = "") =
            """
                <!DOCTYPE html>
                <html>
                <head>
                </head>
                <body>
                <pre id="content">$content</pre>
                </body>
                </html>
            """.trimIndent()
    }

    private val formatter = Formatter(false, 4, asHTML = true, isIntrospection = isIntrospection)

    init {
        this.putClientProperty(HONOR_DISPLAY_PROPERTIES, true)
        this.text = getHTML()
        if (readOnly) this.isEditable = false

        val doc = this.document as HTMLDocument
        doc.styleSheet.addRule(Style.getStyleCSS())
        Burp.Montoya.userInterface().applyThemeToComponent(this)

        // Copy Burp's editor background
        val raw = Burp.Montoya.userInterface().createRawEditor().getTextAreaComponent()
        this.background = raw.background
    }

    fun setFontInHTML(f: Font) {
        this.font = f
        val doc = this.document as HTMLDocument
        val rule = doc.styleSheet.getRule("body")
        StyleConstants.setFontFamily(rule, f.family)
        StyleConstants.setFontSize(rule, f.size)
    }

    fun getQuery(): String {
        val doc = this.document as HTMLDocument
        val pre = doc.getElement("content")
        val content = doc.getText(pre.startOffset, pre.endOffset - pre.startOffset)
        return stripHTML(content)
    }

    fun setQuery(s: String) {
        this.text = getHTML(formatter.format(s))
        this.caretPosition = 0
    }
}