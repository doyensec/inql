package inql.schema.corrections

import org.json.JSONArray

object GraphQLErrorPathParser {
    data class ArgumentPath(
        val rootType: String,
        val fieldName: String,
        val argumentName: String,
    )

    fun parseArgumentPath(primary: JSONArray?, fallback: JSONArray? = null): ArgumentPath? {
        val path = primary ?: fallback ?: return null
        val segments = (0 until path.length()).mapNotNull { index ->
            when (val value = path.opt(index)) {
                is String -> value
                else -> value?.toString()
            }
        }
        if (segments.size < 3) return null

        val rootType = operationRootType(segments[0]) ?: return null
        return ArgumentPath(
            rootType = rootType,
            fieldName = segments[1],
            argumentName = segments[2],
        )
    }

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

    fun pathKey(path: JSONArray?): String? {
        if (path == null || path.length() == 0) return null
        val segments = (0 until path.length()).mapNotNull { index ->
            when (val value = path.opt(index)) {
                is String -> value
                else -> value?.toString()
            }
        }
        val trimmed = segments.dropWhile { operationRootType(it) != null }
        return trimmed.joinToString("/").takeIf { it.isNotEmpty() }
    }
}
