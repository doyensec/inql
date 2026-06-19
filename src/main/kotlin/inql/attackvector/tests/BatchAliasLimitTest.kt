package inql.attackvector.tests

import inql.attackvector.ProbeUtils
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object BatchAliasLimitTest : ScannerTest {
    override val id = "batch_alias"
    override val name = "Batch Query Limits (Alias)"

    override suspend fun run(context: ScanContext): TestResult {
        val maxBatch = context.config.maxBatchSize
        var lastAccepted = 0
        var limitAt: Int? = null
        var lastEvidence: TestEvidence? = null

        for (count in ProbeUtils.generateProbeCounts(maxBatch)) {
            context.ensureActive()
            val aliases = (0 until count).joinToString(" ") { "op$it: __typename" }
            val query = "query { $aliases }"
            val (response, evidence) = context.http.sendQueryExchange(query)
            lastEvidence = evidence
            when (ProbeUtils.classifyBatchJson(response)) {
                ProbeUtils.BatchProbeStatus.ACCEPTED -> lastAccepted = count
                ProbeUtils.BatchProbeStatus.REJECTED -> {
                    limitAt = count
                    break
                }
                ProbeUtils.BatchProbeStatus.AMBIGUOUS -> {
                    return TestResult(
                        name,
                        TestStatus.UNCERTAIN,
                        "Ambiguous alias batch response at $count aliases (HTTP ${evidence?.statusCode ?: 0}).",
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
                    limitLabel = "alias batch",
                    unit = "aliases",
                    configuredMax = maxBatch,
                    limitAt = limitAt,
                    lastSuccessful = lastAccepted,
                ),
                lastEvidence,
            )
            lastAccepted >= maxBatch -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "No alias batch limit detected up to $lastAccepted aliases (configured max: $maxBatch).",
                lastEvidence,
            )
            lastAccepted > 0 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Alias batching accepted up to $lastAccepted aliases but could not probe higher.",
                lastEvidence,
            )
            else -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Alias batching rejected or unavailable.",
                lastEvidence,
            )
        }
    }
}
