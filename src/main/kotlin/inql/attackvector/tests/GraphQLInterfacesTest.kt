package inql.attackvector.tests

import inql.BurpScannerCheck
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object GraphQLInterfacesTest : ScannerTest {
    override val id = "graphql_interfaces"
    override val name = "GraphQL Interfaces (Discovery of /graphiql, /graphql, etc.)"

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
        "__schema",
        "introspection",
    )

    override suspend fun run(context: ScanContext): TestResult {
        val discovered = mutableListOf<String>()
        val probed = mutableListOf<String>()
        var lastEvidence: TestEvidence? = null

        for (path in INTERFACE_PATHS.distinct()) {
            context.ensureActive()
            for (exchange in listOf(context.http.probePath(path), context.http.probePathGet(path))) {
                val method = exchange.request.method()
                probed.add("$path [$method] (HTTP ${exchange.statusCode})")
                if (exchange.statusCode !in 200..399) continue

                val bodyLower = exchange.body.lowercase()
                val marker = INTERFACE_MARKERS.firstOrNull { bodyLower.contains(it.lowercase()) }
                if (marker != null || looksLikeGraphqlEndpoint(bodyLower)) {
                    discovered.add("$path [$method] (HTTP ${exchange.statusCode}, marker: ${marker ?: "graphql-like"})")
                    lastEvidence = exchange.toEvidence()
                }
            }
        }

        return when {
            discovered.isNotEmpty() -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "Discovered ${discovered.size} interface(s):\n${discovered.joinToString("\n")}",
                lastEvidence,
            )
            else -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                buildString {
                    append("No common GraphQL interfaces discovered on the probed paths (GET and POST).")
                    append("\n\nEndpoints tried:\n")
                    append(probed.joinToString("\n"))
                },
            )
        }
    }

    private fun looksLikeGraphqlEndpoint(body: String): Boolean {
        return body.contains("graphql") && (
            body.contains("<html") ||
                body.contains("<!doctype") ||
                body.contains("react")
            )
    }
}
