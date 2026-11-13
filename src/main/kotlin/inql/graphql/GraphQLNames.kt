package inql.graphql

private val NAME_REGEX = Regex("^[_A-Za-z][_0-9A-Za-z]*$")

internal val RESERVED_LITERALS = setOf("true", "false", "null")

internal fun isGraphQLName(value: String) = NAME_REGEX.matches(value)
