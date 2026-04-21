package inql.graphql.scanners

import inql.graphql.GQLSchema

/**
 * A single detected cycle: root field path through the schema where a type/field pair repeats.
 */
data class CycleResult(
    val operationType: GQLSchema.OperationType,
    val pathFieldNames: List<String>,
    /** Index in [pathFieldNames] where the repeating loop starts (first occurrence of the closing edge). */
    val cycleRepeatStartIndex: Int,
) {
    val entrypoint: String get() = pathFieldNames.firstOrNull() ?: ""
    val depth: Int get() = pathFieldNames.size

    /** Path as shown in the scanner table and export (arrow separators). */
    fun pathPreview(): String = pathFieldNames.joinToString(" -> ")
}
