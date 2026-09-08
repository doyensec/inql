package inql.attackvector

import org.json.JSONArray
import org.json.JSONObject

object ProbeUtils {
    enum class LimitProbeStatus { SUCCESS, LIMITED, AMBIGUOUS }
    enum class BatchProbeStatus { ACCEPTED, REJECTED, AMBIGUOUS }

    data class LimitProbeSample(
        val status: LimitProbeStatus,
        val evidence: TestEvidence?,
        val errorMessage: String? = null,
    )

    data class LimitLabels(
        val limitLabel: String,
        val unit: String,
        val inaccessible: (size: Int, statusCode: Int) -> String,
        val ambiguous: (size: Int, statusCode: Int) -> String,
        val noLimit: (lastSuccessful: Int, configuredMax: Int) -> String,
        val partial: (lastSuccessful: Int, configuredMax: Int) -> String,
        val zeroDetail: String,
        val zeroStatus: TestStatus = TestStatus.UNCERTAIN,
    )

    fun generateProbeCounts(max: Int): List<Int> {
        if (max <= 0) return emptyList()
        val counts = linkedSetOf(1, max)
        for (checkpoint in listOf(2, 3, 5, 10, 15, 20, 30, 50, 75, 100, 150, 200, 300, 400, 500, 600, 700, 800, 900)) {
            if (checkpoint <= max) counts.add(checkpoint)
        }
        if (max > 10) counts.add(max / 2)
        if (max > 4) counts.add((max * 3) / 4)
        return counts.sorted()
    }

    fun formatLimitEnforcedDetails(
        limitLabel: String,
        unit: String,
        configuredMax: Int,
        limitAt: Int,
        lastSuccessful: Int,
        errorMessage: String? = null,
    ): String {
        return buildString {
            append("Server enforces a $limitLabel limit at approximately $limitAt $unit")
            if (limitAt < configuredMax) {
                append(" (below your configured maximum of $configuredMax)")
            }
            append(". Last successful probe: $lastSuccessful $unit.")
            if (lastSuccessful in 1 until limitAt) {
                append(" The effective limit is likely between $lastSuccessful and $limitAt.")
            }
            errorMessage?.takeIf { it.isNotBlank() }?.let { append(" Error: $it") }
        }
    }

    suspend fun runLimitScan(
        context: ScanContext,
        name: String,
        configuredMax: Int,
        labels: LimitLabels,
        probe: suspend (Int) -> LimitProbeSample,
    ): TestResult {
        var lastSuccessful = 0
        var limitAt: Int? = null
        var limitMessage: String? = null
        var lastEvidence: TestEvidence? = null
        var ambiguousEvidence: TestEvidence? = null
        var ambiguousSize = 0
        var ambiguousStatusCode = 0

        for (size in generateProbeCounts(configuredMax)) {
            context.ensureActive()
            val sample = probe(size)
            lastEvidence = sample.evidence
            when (sample.status) {
                LimitProbeStatus.SUCCESS -> lastSuccessful = size
                LimitProbeStatus.LIMITED -> {
                    limitAt = size
                    limitMessage = sample.errorMessage
                    break
                }
                LimitProbeStatus.AMBIGUOUS -> {
                    // Keep prior successes; only hard-fail when nothing worked yet.
                    if (lastSuccessful > 0) {
                        ambiguousEvidence = sample.evidence
                        ambiguousSize = size
                        ambiguousStatusCode = sample.evidence?.statusCode ?: 0
                        break
                    }
                    val statusCode = sample.evidence?.statusCode ?: 0
                    val status = if (statusCode in 400..499) TestStatus.INACCESSIBLE else TestStatus.UNCERTAIN
                    val details = if (statusCode in 400..499) {
                        labels.inaccessible(size, statusCode)
                    } else {
                        labels.ambiguous(size, statusCode)
                    }
                    return TestResult(name, status, details, sample.evidence)
                }
            }
        }

        return when {
            limitAt != null -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                formatLimitEnforcedDetails(
                    limitLabel = labels.limitLabel,
                    unit = labels.unit,
                    configuredMax = configuredMax,
                    limitAt = limitAt,
                    lastSuccessful = lastSuccessful,
                    errorMessage = limitMessage,
                ),
                lastEvidence,
            )
            lastSuccessful >= configuredMax -> TestResult(
                name,
                TestStatus.VULNERABLE,
                labels.noLimit(lastSuccessful, configuredMax),
                lastEvidence,
            )
            lastSuccessful > 0 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                buildString {
                    append(labels.partial(lastSuccessful, configuredMax))
                    if (ambiguousSize > 0) {
                        append(" Higher probe at $ambiguousSize ${labels.unit} was ambiguous")
                        if (ambiguousStatusCode > 0) append(" (HTTP $ambiguousStatusCode)")
                        append(".")
                    }
                },
                ambiguousEvidence ?: lastEvidence,
            )
            else -> TestResult(name, labels.zeroStatus, labels.zeroDetail, lastEvidence)
        }
    }

    fun toLimitStatus(status: BatchProbeStatus): LimitProbeStatus = when (status) {
        BatchProbeStatus.ACCEPTED -> LimitProbeStatus.SUCCESS
        BatchProbeStatus.REJECTED -> LimitProbeStatus.LIMITED
        BatchProbeStatus.AMBIGUOUS -> LimitProbeStatus.AMBIGUOUS
    }

    fun extractErrorSummary(json: JSONObject?): String? {
        val errors = json?.optJSONArray("errors") ?: return null
        if (errors.length() == 0) return null
        return errors.optJSONObject(0)?.optString("message")?.takeIf { it.isNotBlank() }
    }

    fun htmlEscape(text: String): String {
        return text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
    }

    fun classifyBatchResponse(exchange: ScanHttpClient.HttpExchange): BatchProbeStatus {
        if (exchange.statusCode in 500..599) return BatchProbeStatus.AMBIGUOUS

        exchange.asJsonArrayOrNull()?.let { array ->
            return classifyBatchArray(array)
        }

        exchange.asJsonOrNull()?.let { json ->
            return classifyBatchJson(json)
        }

        return BatchProbeStatus.AMBIGUOUS
    }

    fun classifyBatchJson(json: JSONObject?): BatchProbeStatus {
        if (json == null) return BatchProbeStatus.AMBIGUOUS
        val signal = batchLimitSignal(json.optJSONArray("errors"))
        if (json.optJSONObject("data") != null) {
            return if (signal == RejectionSignal.STRONG) BatchProbeStatus.REJECTED else BatchProbeStatus.ACCEPTED
        }
        return when (signal) {
            RejectionSignal.STRONG -> BatchProbeStatus.REJECTED
            else -> BatchProbeStatus.AMBIGUOUS
        }
    }

    private fun classifyBatchArray(array: JSONArray): BatchProbeStatus {
        if (array.length() == 0) return BatchProbeStatus.AMBIGUOUS

        var hasData = false
        var hasStrongLimitError = false
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            if (item.optJSONObject("data") != null) {
                hasData = true
            }
            if (batchLimitSignal(item.optJSONArray("errors")) == RejectionSignal.STRONG) {
                hasStrongLimitError = true
            }
        }

        // Prefer limit signal over partial success (servers may execute some ops then reject).
        return when {
            hasStrongLimitError -> BatchProbeStatus.REJECTED
            hasData -> BatchProbeStatus.ACCEPTED
            else -> BatchProbeStatus.AMBIGUOUS
        }
    }

    private fun batchLimitSignal(errors: JSONArray?): RejectionSignal {
        if (errors == null) return RejectionSignal.NONE
        return GraphqlProbe.signalFor(errors.toString(), batchLimitStrongPhrases, batchLimitWeakPhrases)
    }

    private val batchLimitStrongPhrases = listOf(
        "batch size",
        "batch limit",
        "batching not",
        "batching is not",
        "batching disabled",
        "too many operations",
        "too many queries",
        "too many graphql operations",
        "maximum number of operations",
        "maximum operations",
        "max operations",
        "operations limit",
        "operation limit",
        "query batch limit",
        "batch of operations",
        "exceeded the maximum number of",
        "requests in a batch",
    )

    private val batchLimitWeakPhrases = listOf(
        "batch",
        "limit",
        "too many",
        "maximum",
        "exceeded",
        "operations",
    )
}
