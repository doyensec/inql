package inql.attackvector.tests

import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object BatchArrayLimitTest : ScannerTest {
    override val id = "batch_array"
    override val name = "Batch Query Limits (Array)"
    override val description = "Tests whether array-based batched operations are accepted without a size limit."

    override suspend fun run(context: ScanContext): TestResult {
        val maxBatch = context.config.maxBatchSize
        return ProbeUtils.runLimitScan(
            context = context,
            name = name,
            configuredMax = maxBatch,
            labels = ProbeUtils.LimitLabels(
                limitLabel = "array batch",
                unit = "operations",
                inaccessible = { _, statusCode ->
                    "Array batch probe inaccessible (HTTP $statusCode)."
                },
                ambiguous = { count, statusCode ->
                    "Ambiguous array batch response at $count operations (HTTP $statusCode)."
                },
                noLimit = { lastAccepted, configuredMax ->
                    "No array batch limit detected up to $lastAccepted operations (configured max: $configuredMax)."
                },
                partial = { lastAccepted, _ ->
                    "Array batching accepted up to $lastAccepted operations but could not probe higher."
                },
                zeroDetail = "Array batching rejected or unavailable.",
                zeroStatus = TestStatus.NOT_VULNERABLE,
            ),
        ) { count ->
            val exchange = context.http.sendBatchArray(count)
            ProbeUtils.LimitProbeSample(
                status = ProbeUtils.toLimitStatus(ProbeUtils.classifyBatchResponse(exchange)),
                evidence = exchange.toEvidence(),
            )
        }
    }
}
