package inql.attackvector

import inql.ui.HtmlDocument

object ScanResultDetailsRenderer {
    fun render(result: TestResult): String {
        return when (result.detailsFormat) {
            DetailsFormat.HTML -> result.details
            DetailsFormat.PLAIN -> HtmlDocument.wrap(
                renderPlainBody(result.details, result.status),
            )
        }
    }

    private fun renderPlainBody(text: String, status: TestStatus): String {
        val escaped = ProbeUtils.htmlEscape(text)
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\n", "<br>")
        return """
            <p class="${HtmlDocument.statusClass(status)}" style="margin: 0;">
            $escaped
            </p>
        """.trimIndent()
    }
}
