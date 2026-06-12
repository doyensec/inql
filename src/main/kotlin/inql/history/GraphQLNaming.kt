package inql.history

internal fun String.toGraphQLPascalCase(): String {
    if (isBlank()) return this
    return replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
}
