package inql.schema.corrections

import burp.api.montoya.core.ByteArray

/**
 * Parses high-confidence GraphQL validation hints such as unknown-type "Did you mean" messages.
 */
object GraphQLTypeSuggestionParser {
    data class TypeRenameSuggestion(
        val wrongType: String,
        val suggestedType: String,
    )

    private val unknownTypeDidYouMean = Regex(
        """Unknown\s+type\s+\\?["']?(?<wrong>[_A-Za-z][_0-9A-Za-z]*)\\?["']?\s*\.?\s*Did you mean\s+\\?["']?(?<suggested>[_A-Za-z][_0-9A-Za-z]*)\\?["']?\??""",
        RegexOption.IGNORE_CASE,
    )

    /**
     * Cheap check that never decodes or parses the body, so callers on the UI thread can skip the full JSON parse
     * when it returns `false`.
     */
    fun mightContainTypeRenameSuggestions(responseBody: ByteArray): Boolean {
        // Only "mean" is searched: the JSON body may encode the spaces of "Did you mean" (e.g. as \u0020).
        return responseBody.length() > 0 && responseBody.indexOf("mean", false) >= 0
    }

    fun parseTypeRenameSuggestions(responseBody: String?): List<TypeRenameSuggestion> {
        return GraphQLErrorResponseParser.errorMessages(responseBody)
            .flatMap { parseTypeRenameFromMessage(it) }
            .distinctBy { it.wrongType to it.suggestedType }
    }

    private fun parseTypeRenameFromMessage(message: String): List<TypeRenameSuggestion> {
        val match = unknownTypeDidYouMean.find(message) ?: return emptyList()
        val wrong = GraphQLErrorPathParser.normalizeTypeName(match.groups["wrong"]?.value) ?: return emptyList()
        val suggested = GraphQLErrorPathParser.normalizeTypeName(match.groups["suggested"]?.value) ?: return emptyList()
        if (wrong == suggested) return emptyList()
        return listOf(
            TypeRenameSuggestion(
                wrongType = wrong,
                suggestedType = suggested,
            ),
        )
    }
}
