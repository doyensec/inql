package inql.attackvector

import inql.fingerprinter.EngineFingerprintReport
import java.awt.Color

object ScanResultDetailsRenderer {
    fun render(result: TestResult): String {
        return when (result.detailsFormat) {
            DetailsFormat.HTML -> result.details
            DetailsFormat.MARKDOWN -> EngineFingerprintReport.htmlForMarkdown(result.details)
            DetailsFormat.PLAIN -> EngineFingerprintReport.wrapHtmlBody(
                renderPlainBody(result.details, ScanResultsTable.statusColor(result.status)),
            )
        }
    }

    private fun renderPlainBody(text: String, color: Color): String {
        val escaped = text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\n", "<br>")
        return """
            <p style="color: rgb(${color.red},${color.green},${color.blue}); margin: 0;">
            $escaped
            </p>
        """.trimIndent()
    }
}
