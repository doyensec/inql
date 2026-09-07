package inql.attackvector.tests

import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object QueryDepthLimitTest : ScannerTest {
    override val id = "query_depth"
    override val name = "Query Depth Limits"
    override val description = "Probes nested queries to detect whether the server enforces a maximum depth limit."

    override suspend fun run(context: ScanContext): TestResult {
        val maxDepth = context.config.maxDepth
        var lastSuccessfulDepth = 0
        var limitDetectedAt: Int? = null
        var limitMessage: String? = null
        var lastEvidence: TestEvidence? = null

        for (depth in ProbeUtils.generateProbeCounts(maxDepth)) {
            context.ensureActive()
            val query = generateDepthQuery(depth)
            val (response, evidence) = context.http.sendQueryExchange(query)
            lastEvidence = evidence
            val status = classifyDepthResponse(response, depth)

            when (status) {
                DepthProbeStatus.SUCCESS -> lastSuccessfulDepth = depth
                DepthProbeStatus.LIMITED -> {
                    limitDetectedAt = depth
                    limitMessage = extractErrorSummary(response)
                    break
                }
                DepthProbeStatus.AMBIGUOUS -> {
                    val statusCode = evidence?.statusCode ?: 0
                    if (statusCode in 400..499) {
                        return TestResult(
                            name,
                            TestStatus.INACCESSIBLE,
                            "Depth probe inaccessible at depth $depth (HTTP $statusCode).",
                            evidence,
                        )
                    }
                    return TestResult(
                        name,
                        TestStatus.UNCERTAIN,
                        "Ambiguous response at depth $depth (HTTP $statusCode; no clear depth-limit message).",
                        evidence,
                    )
                }
            }
        }

        return when {
            limitDetectedAt != null -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                ProbeUtils.formatLimitEnforcedDetails(
                    limitLabel = "query depth",
                    unit = "levels",
                    configuredMax = maxDepth,
                    limitAt = limitDetectedAt,
                    lastSuccessful = lastSuccessfulDepth,
                    errorMessage = limitMessage,
                ),
                lastEvidence,
            )
            lastSuccessfulDepth >= maxDepth -> TestResult(
                name,
                TestStatus.VULNERABLE,
                "No depth limit detected up to the configured maximum of $maxDepth.",
                lastEvidence,
            )
            else -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Could not determine depth limit behavior (last successful depth: $lastSuccessfulDepth).",
                lastEvidence,
            )
        }
    }

    private enum class DepthProbeStatus { SUCCESS, LIMITED, AMBIGUOUS }

    /**
     * Builds an introspection depth probe where [depth] is the number of nested
     * selections in the chain (alternating fields/type on __Type / __Field).
     */
    internal fun generateDepthQuery(depth: Int): String {
        val inner = buildString {
            repeat(depth) { level ->
                append(if (level % 2 == 0) "fields { " else "type { ")
            }
            append("__typename")
            repeat(depth) {
                append(" }")
            }
        }
        return "query { __schema { types { $inner } } }"
    }

    private fun classifyDepthResponse(response: org.json.JSONObject, depth: Int): DepthProbeStatus {
        if (response.optJSONObject("data")?.has("__schema") == true) {
            return DepthProbeStatus.SUCCESS
        }

        val errorsText = response.optJSONArray("errors")?.toString()?.lowercase() ?: ""
        if (errorsText.isBlank() && response.length() == 0) {
            return DepthProbeStatus.AMBIGUOUS
        }

        val limitKeywords = listOf(
            "depth",
            "too deep",
            "max depth",
            "maximum depth",
            "query is too complex",
            "complexity",
            "exceeded",
        )
        if (limitKeywords.any { errorsText.contains(it) }) {
            return DepthProbeStatus.LIMITED
        }

        return if (depth > 1) DepthProbeStatus.LIMITED else DepthProbeStatus.AMBIGUOUS
    }

    private fun extractErrorSummary(response: org.json.JSONObject): String? {
        val errors = response.optJSONArray("errors") ?: return null
        if (errors.length() == 0) return null
        return errors.getJSONObject(0).optString("message").takeIf { it.isNotBlank() }
    }
}
