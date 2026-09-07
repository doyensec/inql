package inql.attackvector.tests

import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object QueryComplexityLimitTest : ScannerTest {
    override val id = "query_complexity"
    override val name = "Query Complexity Limits"
    override val description = "Sends increasingly expensive queries to detect complexity or cost limits."

    override suspend fun run(context: ScanContext): TestResult {
        val maxComplexity = context.config.maxComplexity
        var lastSuccessful = 0
        var limitAt: Int? = null
        var limitMessage: String? = null
        var lastEvidence: TestEvidence? = null

        for (weight in ProbeUtils.generateProbeCounts(maxComplexity)) {
            context.ensureActive()
            val query = generateComplexityQuery(weight)
            val (response, evidence) = context.http.sendQueryExchange(query)
            lastEvidence = evidence
            val status = classifyComplexityResponse(response)

            when (status) {
                ComplexityProbeStatus.SUCCESS -> lastSuccessful = weight
                ComplexityProbeStatus.LIMITED -> {
                    limitAt = weight
                    limitMessage = extractErrorSummary(response)
                    break
                }
                ComplexityProbeStatus.AMBIGUOUS -> {
                    val statusCode = evidence?.statusCode ?: 0
                    if (statusCode in 400..499) {
                        return TestResult(
                            name,
                            TestStatus.INACCESSIBLE,
                            "Complexity probe inaccessible at weight $weight (HTTP $statusCode).",
                            evidence,
                        )
                    }
                    return TestResult(
                        name,
                        TestStatus.UNCERTAIN,
                        "Ambiguous response when probing complexity weight $weight (HTTP $statusCode).",
                        evidence,
                    )
                }
            }
        }

        return when {
            limitAt != null -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                ProbeUtils.formatLimitEnforcedDetails(
                    limitLabel = "query complexity",
                    unit = "weight",
                    configuredMax = maxComplexity,
                    limitAt = limitAt,
                    lastSuccessful = lastSuccessful,
                    errorMessage = limitMessage,
                ),
                lastEvidence,
            )
            lastSuccessful >= maxComplexity -> TestResult(
                name,
                TestStatus.VULNERABLE,
                "No complexity limit detected up to weight $lastSuccessful (configured max: $maxComplexity).",
                lastEvidence,
            )
            lastSuccessful > 0 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Inconclusive complexity testing (last successful weight: $lastSuccessful of $maxComplexity).",
                lastEvidence,
            )
            else -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Could not determine complexity limit behavior.",
                lastEvidence,
            )
        }
    }

    private enum class ComplexityProbeStatus { SUCCESS, LIMITED, AMBIGUOUS }

    /**
     * Builds a heavy introspection query by widening field metadata and nesting `ofType` selections.
     * This targets field-cost/complexity analyzers rather than alias-count limits.
     */
    internal fun generateComplexityQuery(weight: Int): String {
        val depth = weight.coerceAtLeast(1)
        val typeNest = buildString {
            repeat(depth) {
                append("ofType { name kind description ")
            }
            append("name kind")
            repeat(depth) {
                append(" }")
            }
        }
        return """
            query ComplexityProbe {
              __schema {
                types {
                  fields {
                    name
                    description
                    isDeprecated
                    deprecationReason
                    args {
                      name
                      description
                      defaultValue
                      type { $typeNest }
                    }
                    type { $typeNest }
                  }
                }
              }
            }
        """.trimIndent()
    }

    private fun classifyComplexityResponse(response: org.json.JSONObject): ComplexityProbeStatus {
        if (response.optJSONObject("data")?.optJSONObject("__schema") != null) {
            return ComplexityProbeStatus.SUCCESS
        }

        val errorsText = response.optJSONArray("errors")?.toString()?.lowercase() ?: ""
        if (errorsText.isBlank() && response.length() == 0) {
            return ComplexityProbeStatus.AMBIGUOUS
        }

        val limitKeywords = listOf(
            "complexity",
            "too complex",
            "cost",
            "limit",
            "exceeded",
            "max",
        )
        if (limitKeywords.any { errorsText.contains(it) }) {
            return ComplexityProbeStatus.LIMITED
        }

        return ComplexityProbeStatus.AMBIGUOUS
    }

    private fun extractErrorSummary(response: org.json.JSONObject): String? {
        val errors = response.optJSONArray("errors") ?: return null
        if (errors.length() == 0) return null
        return errors.getJSONObject(0).optString("message").takeIf { it.isNotBlank() }
    }
}
