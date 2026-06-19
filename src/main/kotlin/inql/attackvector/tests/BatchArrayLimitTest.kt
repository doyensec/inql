package inql.attackvector.tests

import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object BatchArrayLimitTest : ScannerTest {
    override val id = "batch_array"
    override val name = "Batch Query Limits (Array)"

    override suspend fun run(context: ScanContext): TestResult {
        val maxBatch = context.config.maxBatchSize
        var lastAccepted = 0
        var limitAt: Int? = null
        var lastEvidence: TestEvidence? = null

        for (count in ProbeUtils.generateProbeCounts(maxBatch)) {
            context.ensureActive()
            val exchange = context.http.sendBatchArray(count)
            lastEvidence = exchange.toEvidence()
            when (ProbeUtils.classifyBatchResponse(exchange)) {
                ProbeUtils.BatchProbeStatus.ACCEPTED -> lastAccepted = count
                ProbeUtils.BatchProbeStatus.REJECTED -> {
                    limitAt = count
                    break
                }
                ProbeUtils.BatchProbeStatus.AMBIGUOUS -> {
                    return TestResult(
                        name,
                        TestStatus.UNCERTAIN,
                        "Ambiguous array batch response at $count operations (HTTP ${exchange.statusCode}).",
                        lastEvidence,
                    )
                }
            }
        }

        return when {
            limitAt != null -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                ProbeUtils.formatLimitEnforcedDetails(
                    limitLabel = "array batch",
                    unit = "operations",
                    configuredMax = maxBatch,
                    limitAt = limitAt,
                    lastSuccessful = lastAccepted,
                ),
                lastEvidence,
            )
            lastAccepted >= maxBatch -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "No array batch limit detected up to $lastAccepted operations (configured max: $maxBatch).",
                lastEvidence,
            )
            lastAccepted > 0 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Array batching accepted up to $lastAccepted operations but could not probe higher.",
                lastEvidence,
            )
            else -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Array batching rejected or unavailable.",
                lastEvidence,
            )
        }
    }
}
