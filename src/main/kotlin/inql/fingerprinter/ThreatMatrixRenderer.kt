package inql.fingerprinter

import inql.attackvector.ProbeUtils.htmlEscape
import inql.fingerprinter.ThreatMatrix.FeatureDefinition
import inql.fingerprinter.ThreatMatrix.FeatureState
import inql.ui.HtmlDocument

/**
 * Renders a [ThreatMatrix.Engine] as HTML tables styled like the Attack Vector scanner's results table.
 * Colors come from the CSS classes of [HtmlDocument], so the report follows the Burp theme.
 */
object ThreatMatrixRenderer {
    /** Inline because Swing ignores padding set through a class on table cells. */
    private const val CELL_PADDING = "padding: 3px 8px;"

    private data class Row(val definition: FeatureDefinition, val state: FeatureState, val risky: Boolean?)

    fun render(engine: ThreatMatrix.Engine): String = HtmlDocument.wrap(
        buildString {
            appendHeader(engine)
            appendPosture(engine)
            appendVulnerabilities(engine)
        },
    )

    private fun StringBuilder.appendHeader(engine: ThreatMatrix.Engine) {
        append("<h1>${htmlEscape(engine.name)}</h1>")
        append("<p>")
        if (engine.language.isNotEmpty()) {
            append("""<span class="muted">${engine.language.joinToString(", ") { htmlEscape(it) }}</span> &nbsp;|&nbsp; """)
        }
        if (engine.source == engine.docs) {
            append(link(engine.source, "Project page"))
        } else {
            append(link(engine.source, "Source code"))
            append(" &nbsp;|&nbsp; ")
            append(link(engine.docs, "Documentation"))
        }
        append("</p>")
    }

    private fun StringBuilder.appendPosture(engine: ThreatMatrix.Engine) {
        append("<h2>Default security posture</h2>")
        val rows = ThreatMatrix.features.mapNotNull { (key, definition) ->
            engine.features[key]?.let { Row(definition, it, ThreatMatrix.isRisky(definition, it.status)) }
        }
        if (rows.isEmpty()) {
            append("""<p class="muted">No default security posture data is available for this engine.</p>""")
            return
        }

        // Exposed features first, then unknown ones; the definition order is kept within each group.
        val sorted = rows.sortedBy { if (it.risky == true) 0 else if (it.risky == null) 1 else 2 }
        appendTable(listOf("Feature" to 26, "Default" to 15, "Potential Impact" to null), sorted) { row ->
            val impact = buildString {
                when (row.risky) {
                    true -> append(htmlEscape(row.definition.risk))
                    false -> append("""<span class="muted">Not exposed by default</span>""")
                    null -> append("""<span class="muted">Unknown</span>""")
                }
                row.state.note?.let { append("""<br><span class="muted small">${htmlEscape(it)}</span>""") }
            }
            listOf(
                htmlEscape(row.definition.label),
                """<b class="${riskClass(row.risky)}">${row.state.status.label.replace(" ", "&nbsp;")}</b>""",
                impact,
            )
        }
    }

    private fun StringBuilder.appendVulnerabilities(engine: ThreatMatrix.Engine) {
        if (engine.vulnerabilities.isEmpty()) return
        append("<h2>Known vulnerabilities</h2>")
        appendTable(listOf("ID" to 22, "Description" to null), engine.vulnerabilities) {
            listOf(link(it.url, it.id), htmlEscape(it.description))
        }
    }

    /** Columns are given as header to width in percent; a null width takes the remaining space. */
    private fun <T> StringBuilder.appendTable(columns: List<Pair<String, Int?>>, items: List<T>, cells: (T) -> List<String>) {
        append("""<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse: collapse;">""")
        append("<tr>")
        columns.forEach { (header, width) ->
            val widthAttribute = width?.let { """ width="$it%"""" } ?: ""
            append("""<th$widthAttribute class="grid" style="$CELL_PADDING">$header</th>""")
        }
        append("</tr>")
        items.forEachIndexed { index, item ->
            // Alternating rows, like ScanResultsTable.rowBackground().
            append("""<tr class="${if (index % 2 == 0) "row-even" else "row-odd"}">""")
            cells(item).forEach { append("""<td class="grid" style="$CELL_PADDING">$it</td>""") }
            append("</tr>")
        }
        append("</table>")
    }

    private fun riskClass(risky: Boolean?) = when (risky) {
        true -> "risk-exposed"
        false -> "risk-safe"
        null -> "risk-unknown"
    }

    private fun link(url: String, text: String) = """<a href="${htmlEscape(url)}">${htmlEscape(text)}</a>"""
}
