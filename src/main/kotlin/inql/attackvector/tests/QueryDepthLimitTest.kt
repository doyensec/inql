package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.ProbeUtils
import inql.attackvector.RejectionSignal
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import org.json.JSONObject

object QueryDepthLimitTest : ScannerTest {
    override val id = "query_depth"
    override val name = "Query Depth Limits"
    override val description = "Probes nested queries to detect whether the server enforces a maximum depth limit."

    internal val strongDepthLimitPhrases = listOf(
        "query is too deep",
        "maximum depth",
        "max depth",
        "too deep",
        "depth limit",
        "depth exceeded",
        "exceeded maximum depth",
        "exceeds maximum depth",
        "max query depth",
        "maximum query depth",
        "query depth exceeded",
        "query depth limit",
    )

    internal val weakDepthLimitPhrases = listOf("depth")

    override suspend fun run(context: ScanContext): TestResult {
        val maxDepth = context.config.maxDepth

        val baselineExchange = context.http.sendRequest(
            context.http.buildQueryRequest(generateDepthQuery(1)),
        )
        val baselineJson = baselineExchange.asJsonOrNull()
        val baselineText = GraphqlProbe.responseText(baselineJson, baselineExchange.body)
        if (GraphqlProbe.indicatesIntrospectionUnavailable(baselineText)) {
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Depth limit probing requires introspection; __schema is not available on this schema " +
                    "(that does not indicate a depth limit).",
                baselineExchange.toEvidence(),
            )
        }

        return ProbeUtils.runLimitScan(
            context = context,
            name = name,
            configuredMax = maxDepth,
            labels = ProbeUtils.LimitLabels(
                limitLabel = "query depth",
                unit = "levels",
                inaccessible = { depth, statusCode ->
                    "Depth probe inaccessible at depth $depth (HTTP $statusCode)."
                },
                ambiguous = { depth, statusCode ->
                    "Ambiguous response at depth $depth (HTTP $statusCode; no clear depth-limit message)."
                },
                noLimit = { _, configuredMax ->
                    "No depth limit detected up to the configured maximum of $configuredMax."
                },
                partial = { lastSuccessful, configuredMax ->
                    "Could not determine depth limit behavior (last successful depth: $lastSuccessful of $configuredMax)."
                },
                zeroDetail = "Could not determine depth limit behavior.",
            ),
        ) { depth ->
            val (response, evidence) = if (depth == 1) {
                Pair(baselineJson, baselineExchange.toEvidence())
            } else {
                context.http.sendQueryExchange(generateDepthQuery(depth))
            }
            ProbeUtils.LimitProbeSample(
                status = classifyDepthResponse(response),
                evidence = evidence,
                errorMessage = ProbeUtils.extractErrorSummary(response),
            )
        }
    }

    /**
     * Introspection depth probe: alternating `fields` / `type` nesting under `__schema`.
     */
    internal fun generateDepthQuery(depth: Int): String {
        val levels = depth.coerceAtLeast(1)
        val inner = buildString {
            repeat(levels) { level ->
                append(if (level % 2 == 0) "fields { " else "type { ")
            }
            append("__typename")
            repeat(levels) {
                append(" }")
            }
        }
        return "query { __schema { types { $inner } } }"
    }

    private fun classifyDepthResponse(response: JSONObject?): ProbeUtils.LimitProbeStatus {
        if (response == null) return ProbeUtils.LimitProbeStatus.AMBIGUOUS

        val data = response.optJSONObject("data")
        if (data?.has("__schema") == true) {
            return ProbeUtils.LimitProbeStatus.SUCCESS
        }

        val errorsText = response.optJSONArray("errors")?.toString() ?: ""
        if (errorsText.isBlank() && response.length() == 0) {
            return ProbeUtils.LimitProbeStatus.AMBIGUOUS
        }

        // Unknown/missing fields (including __schema) are not depth-limit evidence.
        if (GraphqlProbe.indicatesIntrospectionUnavailable(errorsText) ||
            GraphqlProbe.indicatesUnknownField(errorsText)
        ) {
            return ProbeUtils.LimitProbeStatus.AMBIGUOUS
        }

        return when (GraphqlProbe.signalFor(errorsText, strongDepthLimitPhrases, weakDepthLimitPhrases)) {
            RejectionSignal.STRONG -> ProbeUtils.LimitProbeStatus.LIMITED
            else -> ProbeUtils.LimitProbeStatus.AMBIGUOUS
        }
    }
}
