package inql.schema.corrections

object GraphQLErrorPathParser {
    fun operationRootType(segment: String): String? {
        val lowered = segment.trim().lowercase()
        return when {
            lowered.startsWith("query") -> "Query"
            lowered.startsWith("mutation") -> "Mutation"
            lowered.startsWith("subscription") -> "Subscription"
            else -> null
        }
    }

    fun normalizeTypeName(type: String?): String? {
        return type?.trim()?.removeSuffix("!")?.takeIf { it.isNotBlank() }
    }
}
