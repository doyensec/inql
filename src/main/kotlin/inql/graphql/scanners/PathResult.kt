package inql.graphql.scanners

import inql.graphql.GQLSchema

enum class PathTargetKind {
    TYPE,
    FIELD,
}

/**
 * A single path from a root operation field to a target type or field.
 */
data class PathResult(
    val operationType: GQLSchema.OperationType,
    val pathFieldNames: List<String>,
    val targetKind: PathTargetKind,
    val targetTypeName: String? = null,
    val targetFieldName: String? = null,
) {
    val depth: Int get() = pathFieldNames.size

    val entrypoint: String get() = pathFieldNames.firstOrNull() ?: ""

    /** Path as shown in the results table (arrow separators). */
    fun pathPreview(): String {
        val opLabel = when (operationType) {
            GQLSchema.OperationType.QUERY -> "Query"
            GQLSchema.OperationType.MUTATION -> "Mutation"
            GQLSchema.OperationType.SUBSCRIPTION -> "Subscription"
        }
        if (pathFieldNames.isEmpty()) return opLabel

        val parts = mutableListOf(opLabel)
        if (pathFieldNames.size > 1) {
            parts.addAll(pathFieldNames.dropLast(1))
        }
        val lastField = pathFieldNames.last()
        parts.add(
            when (targetKind) {
                PathTargetKind.TYPE -> "$lastField (${targetTypeName ?: "?"})"
                PathTargetKind.FIELD -> lastField
            },
        )
        return parts.joinToString(" -> ")
    }
}

sealed class PathSearchTarget {
    data class TypeTarget(val typeName: String) : PathSearchTarget()
    data class FieldTarget(
        val fieldName: String,
        val declaringTypeNames: Set<String> = emptySet(),
    ) : PathSearchTarget()
}
