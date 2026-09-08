package inql.attackvector.tests

import inql.BurpScannerCheck
import inql.attackvector.DetailsFormat
import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import inql.fingerprinter.EngineFingerprintReport

object GraphQLInterfacesTest : ScannerTest {
    override val id = "graphql_interfaces"
    override val name = "GraphQL Graphical Interfaces"
    override val description = "Discovers common GraphQL IDE and console paths such as GraphiQL and Playground."

    private val INTERFACE_PATHS = BurpScannerCheck.URLS.toList() + listOf(
        "/v1/graphql",
        "/api/graphql",
        "/query",
        "/playground",
        "/altair",
        "/___graphql",
        "/console",
        "/graphQL",
    )

    private val INTERFACE_MARKERS = BurpScannerCheck.CONSOLE_CHECKS.toList() + listOf(
        "graphiql",
        "graphql playground",
        "graphql console",
        "graphql-playground",
        "altair",
        "altairgraphql",
        "altair-graphql",
        "altairgraphql.init",
    )

    override suspend fun run(context: ScanContext): TestResult {
        val discovered = mutableListOf<String>()
        val probed = mutableListOf<String>()
        var lastEvidence: TestEvidence? = null

        for (path in INTERFACE_PATHS.distinct()) {
            context.ensureActive()
            for (exchange in listOf(context.http.probePath(path), context.http.probePathGet(path))) {
                val method = exchange.request.method()
                probed.add(formatEndpointLine(path, method, exchange.statusCode))
                if (exchange.statusCode !in 200..399) continue

                val bodyLower = exchange.body.lowercase()
                val marker = INTERFACE_MARKERS.firstOrNull { bodyLower.contains(it.lowercase()) }
                if (marker != null || looksLikeGraphqlInterface(path, bodyLower)) {
                    discovered.add(
                        formatEndpointLine(path, method, exchange.statusCode, "marker: ${marker ?: "graphql-like"}"),
                    )
                    lastEvidence = exchange.toEvidence()
                }
            }
        }

        return when {
            discovered.isNotEmpty() -> TestResult(
                name,
                TestStatus.VULNERABLE,
                EngineFingerprintReport.wrapHtmlBody(
                    buildString {
                        append("Discovered ${discovered.size} interface(s):<br>")
                        append(discovered.joinToString("<br>"))
                        append("<br><br>Endpoints tried:<br>")
                        append(probed.joinToString("<br>"))
                    },
                ),
                lastEvidence,
                detailsFormat = DetailsFormat.HTML,
            )
            else -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                EngineFingerprintReport.wrapHtmlBody(
                    buildString {
                        append("No common GraphQL interfaces discovered on the probed paths (GET and POST).")
                        append("<br><br>Endpoints tried:<br>")
                        append(probed.joinToString("<br>"))
                    },
                ),
                detailsFormat = DetailsFormat.HTML,
            )
        }
    }

    private fun formatEndpointLine(
        path: String,
        method: String,
        statusCode: Int,
        extra: String? = null,
    ): String {
        val suffix = if (extra != null) ", $extra" else ""
        val line = "${ProbeUtils.htmlEscape(path)} [$method] (HTTP $statusCode$suffix)"
        val color = if (statusCode in 200..299) "green" else "red"
        return """<font color="$color">$line</font>"""
    }

    private fun looksLikeGraphqlInterface(path: String, body: String): Boolean {
        val isHtml = body.contains("<html") || body.contains("<!doctype") || body.contains("<app-root")
        if (!isHtml) return false

        // Known IDE path returning an HTML app shell is enough (e.g. Altair title-only pages).
        val knownIdePath = path.lowercase().let {
            it.contains("graphiql") ||
                it.contains("playground") ||
                it.contains("altair") ||
                it.contains("___graphql") ||
                it.endsWith("/console") ||
                it.endsWith("/console/")
        }
        if (knownIdePath) return true

        return body.contains("graphql") && (
            body.contains("react") ||
                body.contains("graphiql") ||
                body.contains("playground") ||
                body.contains("altair")
            )
    }
}
