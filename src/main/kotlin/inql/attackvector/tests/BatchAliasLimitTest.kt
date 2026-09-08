package inql.attackvector.tests

import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object BatchAliasLimitTest : ScannerTest {
    override val id = "batch_alias"
    override val name = "Batch Query Limits (Alias)"
    override val description = "Tests whether aliased field batching is accepted without a size limit."

    override suspend fun run(context: ScanContext): TestResult {
        val maxBatch = context.config.maxBatchSize
        return ProbeUtils.runLimitScan(
            context = context,
            name = name,
            configuredMax = maxBatch,
            labels = ProbeUtils.LimitLabels(
                limitLabel = "alias batch",
                unit = "aliases",
                inaccessible = { _, statusCode ->
                    "Alias batch probe inaccessible (HTTP $statusCode)."
                },
                ambiguous = { count, statusCode ->
                    "Ambiguous alias batch response at $count aliases (HTTP $statusCode)."
                },
                noLimit = { lastAccepted, configuredMax ->
                    "No alias batch limit detected up to $lastAccepted aliases (configured max: $configuredMax)."
                },
                partial = { lastAccepted, _ ->
                    "Alias batching accepted up to $lastAccepted aliases but could not probe higher."
                },
                zeroDetail = "Alias batching rejected or unavailable.",
                zeroStatus = TestStatus.NOT_VULNERABLE,
            ),
        ) { count ->
            val aliases = (0 until count).joinToString(" ") { "op$it: __typename" }
            val (response, evidence) = context.http.sendQueryExchange("query { $aliases }")
            ProbeUtils.LimitProbeSample(
                status = ProbeUtils.toLimitStatus(ProbeUtils.classifyBatchJson(response)),
                evidence = evidence,
            )
        }
    }
}
