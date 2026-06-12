package inql.schema.corrections

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLSchema

/**
 * Matches inferred enum types to input object fields (e.g. CweEntryOrderInput.field → CweEntryOrderField).
 */
object InputEnumTypeMatching {
    fun enumNameCandidates(inputTypeName: String, fieldName: String): List<String> {
        val parentBase = inputTypeName.removeSuffix("Input")
        val pascalField = pascalCase(fieldName)
        val candidates = linkedSetOf<String>()
        candidates.add("${parentBase}$pascalField")
        candidates.add("${parentBase}${pascalField}Enum")
        when (fieldName.lowercase()) {
            "direction" -> {
                candidates.add("${parentBase}Direction")
                candidates.add("${parentBase}DirectionEnum")
                candidates.add("OrderDirection")
                candidates.add("SortDirection")
            }
            "field" -> candidates.add("${parentBase}Field")
        }
        candidates.add("${pascalField}Enum")
        return candidates.toList()
    }

    /** Candidates specific to [inputTypeName] + [fieldName], excluding generic names like FieldEnum. */
    fun strongEnumNameCandidates(inputTypeName: String, fieldName: String): List<String> {
        val all = enumNameCandidates(inputTypeName, fieldName)
        val generic = "${pascalCase(fieldName)}Enum"
        return all.filterNot { it.equals(generic, ignoreCase = true) }
    }

    fun preferredEnumNameForInputField(inputTypeName: String, fieldName: String): String {
        return strongEnumNameCandidates(inputTypeName, fieldName).firstOrNull()
            ?: "${inputTypeName.removeSuffix("Input")}${pascalCase(fieldName)}"
    }

    fun resolveEnumForInputField(
        schema: GraphQLSchema,
        inputTypeName: String,
        fieldName: String,
    ): GraphQLEnumType? {
        var best: GraphQLEnumType? = null
        var bestScore = -1
        for ((index, candidate) in enumNameCandidates(inputTypeName, fieldName).withIndex()) {
            val enumType = schema.getType(candidate) as? GraphQLEnumType ?: continue
            val score = (enumNameCandidates(inputTypeName, fieldName).size - index) * 10
            if (score > bestScore) {
                best = enumType
                bestScore = score
            }
        }
        return best
    }

    private fun pascalCase(value: String): String {
        if (value.isEmpty()) return value
        return value.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    }
}
