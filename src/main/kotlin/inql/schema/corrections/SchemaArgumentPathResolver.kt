package inql.schema.corrections

import inql.history.ConnectionNodeTypeNaming
import org.json.JSONArray

object SchemaArgumentPathResolver {
    data class ResolvedArgument(
        val parentType: String,
        val fieldName: String,
        val argumentName: String,
    )

    fun parseArgumentLocation(path: JSONArray?, argumentNameHint: String? = null): Pair<String, String>? {
        val segments = toSegments(path) ?: return null
        if (segments.size >= 2) {
            val argumentName = segments.last()
            val fieldName = segments[segments.size - 2]
            return fieldName to argumentName
        }
        if (segments.size == 1 && !argumentNameHint.isNullOrBlank()) {
            return segments[0] to argumentNameHint
        }
        return null
    }

    fun inferredParentTypeFromErrorPath(path: JSONArray?, fieldName: String): String? {
        val segments = toSegments(path) ?: return null
        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex == 0) {
            return defaultRootTypeName(segments)
        }
        return inferParentTypeNameFromPath(segments, fieldName)
    }

    private fun inferParentTypeNameFromPath(segments: List<String>, fieldName: String): String? {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex <= 0) return null

        val prefix = segments.take(fieldIndex).filterNot { isListIndex(it) }

        val beforeField = prefix.lastOrNull() ?: return null
        if (beforeField.lowercase() !in relaySegments) {
            return segmentToTypeName(beforeField)
        }

        for (index in prefix.indices.reversed()) {
            when (prefix[index].lowercase()) {
                "nodes", "node" -> {
                    if (index > 0 && isDirectConnectionNodeChild(segments, fieldName, index)) {
                        val connectionField = prefix[index - 1]
                        val parentPrefix = prefix.take(index - 1)
                        val parentType = inferParentTypeNameFromPath(
                            parentPrefix + listOf("_"),
                            "_",
                        ) ?: if (parentPrefix.isEmpty()) {
                            defaultRootTypeName(segments)
                        } else {
                            return null
                        }
                        return ConnectionNodeTypeNaming.synthetic(parentType, connectionField)
                    }
                }
            }
        }

        return null
    }

    private fun isDirectConnectionNodeChild(
        segments: List<String>,
        fieldName: String,
        relayIndexInFilteredPrefix: Int,
    ): Boolean {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        val prefix = segments.take(fieldIndex).filterNot { isListIndex(it) }
        if (relayIndexInFilteredPrefix != prefix.size - 1) return false
        val relayIndexInFull = segments.take(fieldIndex).indexOfLast {
            it.equals(prefix[relayIndexInFilteredPrefix], ignoreCase = true)
        }
        if (relayIndexInFull < 0) return false
        return segments.subList(relayIndexInFull + 1, fieldIndex).all { isListIndex(it) }
    }

    private fun segmentToTypeName(segment: String): String {
        return segment.split('_')
            .filter { it.isNotBlank() }
            .joinToString("") { part -> part.replaceFirstChar { char -> char.uppercase() } }
    }

    private val relaySegments = setOf("edges", "node", "nodes", "pageinfo")

    private fun isListIndex(segment: String): Boolean = segment.toIntOrNull() != null

    private fun defaultRootTypeName(segments: List<String>): String {
        return segments.firstOrNull { GraphQLErrorPathParser.operationRootType(it) != null }
            ?.let { GraphQLErrorPathParser.operationRootType(it) }
            ?: "Query"
    }

    private fun toSegments(path: JSONArray?): List<String>? {
        if (path == null || path.length() == 0) return null
        val segments = (0 until path.length()).mapNotNull { index ->
            when (val value = path.opt(index)) {
                is String -> value
                else -> value?.toString()
            }
        }
        val trimmed = segments.dropWhile { segment ->
            GraphQLErrorPathParser.operationRootType(segment) != null
        }
        return trimmed.ifEmpty { null }
    }
}
