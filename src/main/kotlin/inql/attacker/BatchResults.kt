package inql.attacker

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser

enum class BatchItemStatus(val label: String) {
    DATA("Data"),
    NO_DATA("No data"),
    UNPARSED("Not split"),
    FAILED("Request failed"),
}

data class BatchResultItem(
    /** 1-based position of the item across the whole run. */
    val index: Int,
    /** 0-based position of the item within its HTTP request; alias mode names it `op{localIndex}_`. */
    val localIndex: Int,
    val payloads: List<String?>,
    val part: Int,
    val status: BatchItemStatus,
    val errors: String,
    val size: Int?,
    /** Response time of the HTTP request that carried this item. */
    val responseTimeMs: Long?,
) {
    /** Items with the same status and (number-insensitive) error message behave the same way. */
    val groupKey: String = status.name + "|" + errors.replace(Regex("\\d+"), "#")
}

/**
 * Results of one batch attack (one Send click), merged across all of its HTTP requests.
 * Kept in memory for the current session only.
 */
class BatchRun(
    val mode: BatchMode,
    val variableLabels: List<String>,
    val totalItems: Int,
    val partCount: Int,
) {
    val items = ArrayList<BatchResultItem>()
    private val groupSizes = HashMap<String, Int>()
    private var largestGroupSize = 0

    fun addAll(newItems: List<BatchResultItem>) {
        items.addAll(newItems)
        for (item in newItems) {
            val size = groupSizes.merge(item.groupKey, 1, Int::plus)!!
            if (size > largestGroupSize) largestGroupSize = size
        }
    }

    /** True for items whose behaviour is rare compared to the rest of the run (e.g. the one valid OTP). */
    fun isOutlier(item: BatchResultItem): Boolean = isOutlierGroup(groupSizes[item.groupKey] ?: 0)

    fun outlierCount(): Int = groupSizes.values.filter { isOutlierGroup(it) }.sum()

    private fun isOutlierGroup(size: Int): Boolean {
        if (size == 0 || groupSizes.size < 2 || size == largestGroupSize) return false
        return size <= maxOf(1, items.size / 20)
    }
}

data class BatchItemOutcome(val status: BatchItemStatus, val errors: String, val size: Int?)

/** Splits a batched GraphQL response into per-item outcomes. */
object BatchResponseParser {
    private val aliasPrefix = Regex("^op(\\d+)_")

    fun split(mode: BatchMode, itemCount: Int, body: String): List<BatchItemOutcome> {
        val json = try {
            JsonParser.parseString(body)
        } catch (_: Exception) {
            null
        }
        val outcomes = when (mode) {
            BatchMode.ALIAS -> json?.takeIf { it.isJsonObject }?.let { splitAlias(it.asJsonObject, itemCount) }
            BatchMode.ARRAY -> json?.let { splitArray(it, itemCount) }
        }
        return outcomes ?: List(itemCount) { BatchItemOutcome(BatchItemStatus.UNPARSED, "", null) }
    }

    private fun splitAlias(response: JsonObject, itemCount: Int): List<BatchItemOutcome>? {
        val data = response.get("data")?.takeIf { it.isJsonObject }?.asJsonObject
        val errors = errorObjects(response)
        if (data == null && errors.isEmpty()) return null

        val dataByItem = HashMap<Int, MutableList<Map.Entry<String, JsonElement>>>()
        data?.entrySet()?.forEach { entry ->
            itemIndexOf(entry.key)?.let { dataByItem.getOrPut(it) { ArrayList() }.add(entry) }
        }
        val errorsByItem = HashMap<Int, MutableList<JsonObject>>()
        val unattributed = ArrayList<JsonObject>()
        for (error in errors) {
            val key = error.get("path")?.takeIf { it.isJsonArray }?.asJsonArray?.firstOrNull()
                ?.takeIf { it.isJsonPrimitive }?.asString
            val index = key?.let { itemIndexOf(it) }
            if (index != null) errorsByItem.getOrPut(index) { ArrayList() }.add(error) else unattributed.add(error)
        }

        return (0 until itemCount).map { index ->
            val entries = dataByItem[index].orEmpty()
            // Errors without a path (e.g. the whole document was rejected) apply to items with no own result.
            val itemErrors = errorsByItem[index] ?: if (entries.isEmpty()) unattributed else emptyList()
            val hasData = entries.any { !it.value.isJsonNull }
            BatchItemOutcome(
                status = if (hasData) BatchItemStatus.DATA else BatchItemStatus.NO_DATA,
                errors = messages(itemErrors),
                size = entries.sumOf { it.key.length + it.value.toString().length } +
                    itemErrors.sumOf { it.toString().length },
            )
        }
    }

    private fun splitArray(response: JsonElement, itemCount: Int): List<BatchItemOutcome>? {
        if (response.isJsonObject) {
            // The server answered the batch with a single result, e.g. "batching is not supported".
            val outcome = outcomeOf(response.asJsonObject)
            return List(itemCount) { outcome }
        }
        if (!response.isJsonArray) return null
        val array = response.asJsonArray
        return (0 until itemCount).map { index ->
            val element = if (index < array.size()) array.get(index) else null
            if (element != null && element.isJsonObject) {
                outcomeOf(element.asJsonObject)
            } else {
                BatchItemOutcome(BatchItemStatus.UNPARSED, "", null)
            }
        }
    }

    private fun outcomeOf(result: JsonObject): BatchItemOutcome {
        val data = result.get("data")
        val hasData = when {
            data == null || data.isJsonNull -> false
            data.isJsonObject -> data.asJsonObject.entrySet().any { !it.value.isJsonNull }
            else -> true
        }
        return BatchItemOutcome(
            status = if (hasData) BatchItemStatus.DATA else BatchItemStatus.NO_DATA,
            errors = messages(errorObjects(result)),
            size = result.toString().length,
        )
    }

    private fun errorObjects(result: JsonObject): List<JsonObject> {
        val errors = result.get("errors")?.takeIf { it.isJsonArray }?.asJsonArray ?: JsonArray()
        return errors.filter { it.isJsonObject }.map { it.asJsonObject }
    }

    private fun messages(errors: List<JsonObject>): String {
        return errors.mapNotNull { error ->
            error.get("message")?.takeIf { it.isJsonPrimitive }?.asString
        }.distinct().joinToString("; ")
    }

    private fun itemIndexOf(responseKey: String): Int? {
        return aliasPrefix.find(responseKey)?.groupValues?.get(1)?.toIntOrNull()
    }
}
