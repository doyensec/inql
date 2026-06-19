package inql.attackvector

object ProbeUtils {
    /**
     * Sampled probe sizes for limit tests (depth, batch alias/array, complexity).
     * Always includes 1 and [max], with logarithmic-style checkpoints in between.
     */
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

    fun classifyBatchJson(json: org.json.JSONObject): BatchProbeStatus {
        if (json.optJSONObject("data") != null) {
            return BatchProbeStatus.ACCEPTED
        }
        return classifyBatchErrors(json.optJSONArray("errors"))
    }

    private fun classifyBatchArray(array: org.json.JSONArray): BatchProbeStatus {
        if (array.length() == 0) return BatchProbeStatus.AMBIGUOUS

        var hasData = false
        var hasLimitError = false
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            if (item.optJSONObject("data") != null) {
                hasData = true
            }
            if (item.optJSONArray("errors") != null) {
                val errorsText = item.optJSONArray("errors").toString().lowercase()
                if (batchLimitKeywords.any { errorsText.contains(it) }) {
                    hasLimitError = true
                }
            }
        }

        return when {
            hasData -> BatchProbeStatus.ACCEPTED
            hasLimitError -> BatchProbeStatus.REJECTED
            else -> BatchProbeStatus.AMBIGUOUS
        }
    }

    private fun classifyBatchErrors(errors: org.json.JSONArray?): BatchProbeStatus {
        if (errors == null) return BatchProbeStatus.AMBIGUOUS
        val errorsText = errors.toString().lowercase()
        return if (batchLimitKeywords.any { errorsText.contains(it) }) {
            BatchProbeStatus.REJECTED
        } else {
            BatchProbeStatus.AMBIGUOUS
        }
    }

    private val batchLimitKeywords = listOf(
        "batch",
        "limit",
        "too many",
        "maximum",
        "exceeded",
        "operations",
    )

    enum class BatchProbeStatus { ACCEPTED, REJECTED, AMBIGUOUS }
}
