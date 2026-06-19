package inql.fingerprinter

import inql.utils.MarkdownToHtmlConverter
import inql.ui.HtmlScrollPane
import javax.swing.JEditorPane

object EngineFingerprintReport {
    fun markdownForEngine(engineKey: String): String? {
        val details = Helpers.engines[engineKey] ?: return null
        return markdownForEngine(details)
    }

    fun htmlForEngine(engineKey: String): String? {
        return markdownForEngine(engineKey)?.let { htmlForMarkdown(it) }
    }

    fun markdownForEngine(details: Helpers.Companion.EngineDetails): String {
        val body = try {
            MarkdownToHtmlConverter.downloadMarkdown(details.ref)
        } catch (_: Exception) {
            buildFallbackMarkdown(details)
        }
        return "# Server Engine Found: ${details.name}\n$body"
    }

    fun htmlForMarkdown(markdown: String): String {
        val body = normalizeForSwingHtml(MarkdownToHtmlConverter.renderMarkdownToHtml(markdown))
        return wrapHtmlBody(body)
    }

    fun wrapHtmlBody(body: String): String = wrapHtmlDocument(body)

    fun applyHtml(pane: JEditorPane, html: String) {
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, false)
        pane.contentType = "text/html"
        pane.isEditable = false
        pane.text = html
        pane.caretPosition = 0
        HtmlScrollPane.refreshContentSize(pane)
    }

    /**
     * Swing's HTML 3.2 renderer handles [b]/[i] more reliably than [strong]/[em].
     */
    private fun normalizeForSwingHtml(html: String): String {
        return html
            .replace("<strong>", "<b>")
            .replace("</strong>", "</b>")
            .replace("<em>", "<i>")
            .replace("</em>", "</i>")
    }

    private fun wrapHtmlDocument(body: String): String {
        return """
            <html>
              <head>
                <style>
                  body { font-family: sans-serif; padding: 8px; margin: 0; }
                  h1 { font-size: 18px; font-weight: bold; margin: 12px 0 8px 0; }
                  h2 { font-size: 16px; font-weight: bold; margin: 12px 0 8px 0; }
                  h3 { font-size: 14px; font-weight: bold; margin: 10px 0 6px 0; }
                  b { font-weight: bold; }
                  a { color: #0066cc; text-decoration: underline; }
                  ul { margin-left: 20px; }
                  table { border-collapse: collapse; margin: 16px 0; font-family: Arial, sans-serif; }
                  th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
                </style>
              </head>
              <body>
                $body
              </body>
            </html>
        """.trimIndent()
    }

    private fun buildFallbackMarkdown(details: Helpers.Companion.EngineDetails): String {
        return """
            **Name**: ${details.name}
            **Url**: ${details.url}
            **Matrix Reference**: ${details.ref}
            **Technologies**: ${details.technology}
            
            Unable to retrieve GraphQL Threat Matrix data for this engine. The issue is likely external and not caused by InQL.
        """.trimIndent()
    }
}
