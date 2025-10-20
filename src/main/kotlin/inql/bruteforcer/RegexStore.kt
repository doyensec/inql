package inql.bruteforcer

/**
 * A utility object to store regular expressions used for parsing GraphQL error messages.
 * This is central to Clairvoyance's technique of schema reconstruction.
 *
 * This version is expanded to include regexes for multiple server implementations.
 */
object RegexStore {
    val WRONG_TYPENAME = listOf(
        Regex("""Cannot query field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" on type "(?<typename>[_A-Za-z][_0-9A-Za-z]*)".(.*)"""),
        Regex("""Field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' is not defined by type '(?<typename>[_A-Za-z][_0-9A-Za-z]*)'.(.*)"""),
        Regex("""Cannot query field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' on type '(?<typename>[_A-Za-z][_0-9A-Za-z]*)'.(.*)"""),
        Regex("""Field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" is not defined by type "(?<typename>[_A-Za-z][_0-9A-Za-z]*)".?"""),
        Regex("""Field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' doesn't exist on type '(?<typename>[_A-Za-z][_0-9A-Za-z]*)'.*"""),
        Regex("""Field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' doesn't exist on type '(?<typename>[_A-Za-z][_0-9A-Za-z]*)'"""),
    )

    val FIELD_SUGGESTIONS = listOf(
        Regex("""(?:Did you mean|\G(?!^))[^\w"']+["'](?<suggestion>[_A-Za-z][_0-9A-Za-z]*)["']"""),
        Regex("""Did you mean (?<suggestion1>[_A-Za-z][_0-9A-Za-z]*) or (?<suggestion2>[_A-Za-z][_0-9A-Za-z]*)\?"""),
        Regex("""Did you mean (?<suggestion>[_A-Za-z][_0-9A-Za-z]*)\?"""),
    )

    val NO_SUBFIELDS =
        Regex("""Field ["'](?<field>[_A-Za-z][_0-9A-Za-z]*)["'] must not have a selection since type ["']?(?<type>.*?)["']? has no subfields\.*""")

    val SELECTION_ON_SCALAR =
        Regex("""Selections can't be made on scalars \(field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' returns (?<type>[_A-Za-z!\[\]]+) but has selections.*\)""")

    val MISSING_SUBFIELDS =
        Regex("""Field ["'](?<field>[_A-Za-z][_0-9A-Za-z]*)["'] of type ["']?(?<type>.*?)["']? must have a selection of subfields\.*""")

    val WRONG_ARGUMENT_TYPES = listOf(
        Regex("""Argument ['"](?<argument>[_A-Za-z][_0-9A-Za-z]*)['"] has invalid value .* Expected type ['"]?(?<type>[_A-Za-z!\[\]]+)['"]?,?"""),
        Regex("""Expected type (?<type>[_A-Za-z!\[\]]+),? found .*\."""),
        Regex("""Invalid value .* for argument '(?<argument>[_A-Za-z][_0-9A-Za-z]*)' of field '.*': expected type '(?<type>[_A-Za-z!\[\]]+)'"""),
        Regex("""Variable `.*` got invalid value .* expected type `(?<type>[_A-Za-z!\[\]]+)`"""),
        Regex("""Expected type ['"]?(?<type>[_A-Za-z!\[\]]+)['"]? for argument ['"](?<argument>[_A-Za-z][_0-9A-Za-z]*)['"]"""),
        Regex("""Value .* does not exist in enum ['"]?(?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]?"""),
        Regex("""Expected type [`"']?(?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]? to be an enum\."""),
        Regex("""'s value is invalid\. Expected type [`"']?(?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]? enum\."""),
    )

    val MISSING_ARGUMENT =
        Regex("""Field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" argument "(?<argument>[_A-Za-z][_0-9A-Za-z]*)" of type "(?<type>.*)" is required(?:, but it was not provided| but not provided)?\.""")

    val ARGUMENT_SUGGESTIONS = listOf(
        Regex("""Unknown argument "(?<argument>[_A-Za-z][_0-9A-Za-z]*)" on field "(?<field>[_A-Za-z][_0-9A-Za-z]*)".*Did you mean "(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)"\?"""),
        Regex("""Unknown argument '(?<argument>[_A-Za-z][_0-9A-Za-z]*)' on field '(?<field>[_A-Za-z][_0-9A-Za-z]*)'.*Did you mean '(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)'\?"""),
        Regex("""Field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' doesn't accept argument '(?<argument>[_A-Za-z][_0-9A-Za-z]*)'. Did you mean '(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)'\?"""),
    )

    val UNKNOWN_ARGUMENT = listOf(
        Regex("""Unknown argument [`"'](?<argument>[_A-Za-z][_0-9A-Za-z]*)['"'] on field .*"""),
        Regex("""Argument [`"'](?<argument>[_A-Za-z][_0-9A-Za-z]*)['"'] is not defined on field .*"""),
        Regex("""Unknown argument '(?<argument>[_A-Za-z][_0-9A-Za-z]*)' on field '.*'"""),
        Regex("""Field '.*' doesn't accept argument '(?<argument>[_A-Za-z][_0-9A-Za-z]*)'"""),
    )

    val EXPECTED_INPUT_OBJECT =
        Regex("""Expected type (?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+) to be an object\.""")

    val ABSTRACT_TYPE_NO_SELECTION =
        Regex("""Field ["'](?<field>[_A-Za-z][_0-9A-Za-z]*)["'] of abstract type ["']?(?<type>.*?)["']? must have a selection of subfields\.*""")

    val INVALID_FRAGMENT_TYPE =
        Regex("""Fragment cannot be spread here as objects of type ["']?(?<type>.*?)["']? can never be of type ["']?(?<fragment_type>.*?)["']?\.""")

    val INVALID_FRAGMENT_SUGGESTIONS = listOf(
        Regex("""Fragment .* not valid on type [`"'](?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]?\. Did you mean [`"'](?<suggestion>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]?\?"""),
        Regex("""Cannot spread fragment .* on type [`"'](?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]?\. Possible types are: (?<suggestion1>[_A-Za-z][_0-9A-Za-z!\[\]]+), (?<suggestion2>[_A-Za-z][_0-9A-Za-z!\[\]]+)"""),
        Regex("""Possible types are (?<suggestion1>[_A-Za-z][_0-9A-Za-z!\[\]]+), (?<suggestion2>[_A-Za-z][_0-9A-Za-z!\[\]]+) and (?<suggestion3>[_A-Za-z][_0-9A-Za-z!\[\]]+)\."""),
    )

    val SYNTAX_ERROR = listOf(
        Regex("""Syntax Error.*"""),
        Regex(""".*GRAPHQL_PARSE_FAILED.*""")
    )

    // A fake field name used to trigger type name errors
    const val WRONG_FIELD_EXAMPLE = "____i_n_q_l____"
    const val WRONG_ARG_EXAMPLE = "____i_n_q_l____"

    val UNKNOWN_INPUT_FIELD =
        Regex("""Field ['"](?<field>[_A-Za-z][_0-9A-Za-z]*)['"] is not defined by type ['"](?<type>[_A-Za-z][_0-9A-Za-z!\[\]]+)['"]\.""")

    fun getSuggestions(errorMessage: String, regexList: List<Regex>): List<String> {
        val suggestionGroupNames = listOf("suggestion", "suggestion1", "suggestion2")

        return regexList.flatMap { regex ->
            regex.findAll(errorMessage).flatMap { matchResult ->
                suggestionGroupNames.mapNotNull { groupName ->
                    try {
                        matchResult.groups[groupName]?.value
                    } catch (e: NoSuchElementException) {
                        null
                    } catch (e: IllegalArgumentException) {
                        null
                    }
                }
            }
        }.distinct()
    }
}