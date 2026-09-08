package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import org.json.JSONObject

object QueryComplexityLimitTest : ScannerTest {
    override val id = "query_complexity"
    override val name = "Query Complexity Limits"
    override val description = "Sends increasingly expensive queries to detect complexity or cost limits."

    private val complexityLimitPhrases = listOf(
        "too complex",
        "query complexity",
        "complexity limit",
        "complexity exceeded",
        "maximum complexity",
        "max complexity",
        "max query complexity",
        "maximum query complexity",
        "query cost",
        "cost limit",
        "cost exceeded",
        "maximum cost",
        "max cost",
        "query is too complex",
        "exceeded cost",
        "exceeds cost",
        // Broader tokens from the original scanner.
        "complexity",
        "cost",
    )

    override suspend fun run(context: ScanContext): TestResult {
        val maxComplexity = context.config.maxComplexity

        // Complexity probing needs a working __schema query. Unknown/missing __schema proves nothing
        // about cost limits — stop instead of looping ambiguous probes.
        val baselineExchange = context.http.sendRequest(context.http.buildQueryRequest(generateComplexityQuery(1)))
        val baselineJson = baselineExchange.asJsonOrNull()
        val baselineText = GraphqlProbe.responseText(baselineJson, baselineExchange.body)
        if (GraphqlProbe.indicatesIntrospectionUnavailable(baselineText)) {
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Complexity probing requires introspection; __schema is not available on this schema " +
                    "(that does not indicate a complexity limit).",
                baselineExchange.toEvidence(),
            )
        }

        return ProbeUtils.runLimitScan(
            context = context,
            name = name,
            configuredMax = maxComplexity,
            labels = ProbeUtils.LimitLabels(
                limitLabel = "query complexity",
                unit = "weight",
                inaccessible = { weight, statusCode ->
                    "Complexity probe inaccessible at weight $weight (HTTP $statusCode)."
                },
                ambiguous = { weight, statusCode ->
                    "Ambiguous response when probing complexity weight $weight (HTTP $statusCode)."
                },
                noLimit = { lastSuccessful, configuredMax ->
                    "No complexity limit detected up to weight $lastSuccessful (configured max: $configuredMax)."
                },
                partial = { lastSuccessful, configuredMax ->
                    "Inconclusive complexity testing (last successful weight: $lastSuccessful of $configuredMax)."
                },
                zeroDetail = "Could not determine complexity limit behavior.",
            ),
        ) { weight ->
            val (response, evidence) = if (weight == 1) {
                Pair(baselineJson, baselineExchange.toEvidence())
            } else {
                context.http.sendQueryExchange(generateComplexityQuery(weight))
            }
            ProbeUtils.LimitProbeSample(
                status = classifyComplexityResponse(response),
                evidence = evidence,
                errorMessage = ProbeUtils.extractErrorSummary(response),
            )
        }
    }

    /**
     * Heavy introspection probe: widens field metadata and nests `ofType` selections.
     * Targets field-cost/complexity analyzers (not alias-count limits).
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

    private fun classifyComplexityResponse(response: JSONObject?): ProbeUtils.LimitProbeStatus {
        if (response == null) return ProbeUtils.LimitProbeStatus.AMBIGUOUS

        val data = response.optJSONObject("data")
        if (data?.optJSONObject("__schema") != null) {
            return ProbeUtils.LimitProbeStatus.SUCCESS
        }

        val errorsText = response.optJSONArray("errors")?.toString() ?: ""
        if (errorsText.isBlank() && response.length() == 0) {
            return ProbeUtils.LimitProbeStatus.AMBIGUOUS
        }

        // Missing __schema is not a complexity signal (handled up-front, but keep safe here).
        if (GraphqlProbe.indicatesIntrospectionUnavailable(errorsText)) {
            return ProbeUtils.LimitProbeStatus.AMBIGUOUS
        }

        // Depth limiters can still trip on large documents — don't mis-label as complexity.
        val clearDepth = QueryDepthLimitTest.depthLimitPhrases
            .filter { it != "depth" }
            .any { errorsText.lowercase().contains(it) }
        val hasComplexity = GraphqlProbe.containsAny(errorsText, complexityLimitPhrases)
        if (clearDepth && !hasComplexity) {
            return ProbeUtils.LimitProbeStatus.AMBIGUOUS
        }

        if (hasComplexity) {
            return ProbeUtils.LimitProbeStatus.LIMITED
        }

        return ProbeUtils.LimitProbeStatus.AMBIGUOUS
    }
}
