package inql.bruteforcer

import inql.Logger

class RegexStore {
    companion object {
        const val MAIN_REGEX = """[_0-9A-Za-z.\[\]!]+"""
        const val REQUIRED_BUT_NOT_PROVIDED = """required(, but it was not provided| but not provided)?\."""

        val FIELD_REGEXES = mapOf(
            "SKIP" to listOf(
                """Field ['"]$MAIN_REGEX['"] must not have a selection since type ['"]$MAIN_REGEX['"] has no subfields\.""",
                """Field ['"]$MAIN_REGEX['"] argument ['"]$MAIN_REGEX['"] of type ['"]$MAIN_REGEX['"] is $REQUIRED_BUT_NOT_PROVIDED""",
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"]$MAIN_REGEX['"]\.""",
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"]($MAIN_REGEX)['"]\. Did you mean to use an inline fragment on ['"]$MAIN_REGEX['"]\?""",
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"]($MAIN_REGEX)['"]\. Did you mean to use an inline fragment on ['"]$MAIN_REGEX['"] or ['"]$MAIN_REGEX['"]\?""",
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"]($MAIN_REGEX)['"]\. Did you mean to use an inline fragment on (['"]$MAIN_REGEX['"], )+(or ['"]$MAIN_REGEX['"])?\?"""
            ).map { Regex(it) },

            "VALID_FIELD" to listOf(
                """Field ['"](?<field>$MAIN_REGEX)['"] of type ['"](?<typeref>$MAIN_REGEX)['"] must have a selection of subfields\. Did you mean ['"]$MAIN_REGEX( \{ \.\.\. \})?['"]\?""",
                """Field ['"](?<field>$MAIN_REGEX)['"] of type ['"](?<typeref>$MAIN_REGEX)['"] must have a sub selection\."""
            ).map { Regex(it) },

            "SINGLE_SUGGESTION" to listOf(
                """Cannot query field ['"]($MAIN_REGEX)['"] on type ['"]$MAIN_REGEX['"]\. Did you mean ['"](?<field>$MAIN_REGEX)['"]\?"""
            ).map { Regex(it) },

            "DOUBLE_SUGGESTION" to listOf(
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"]$MAIN_REGEX['"]\. Did you mean ['"](?<one>$MAIN_REGEX)['"] or ['"](?<two>$MAIN_REGEX)['"]\?"""
            ).map { Regex(it) },

            "MULTI_SUGGESTION" to listOf(
                """Cannot query field ['"]($MAIN_REGEX)['"] on type ['"]$MAIN_REGEX['"]\. Did you mean (?<multi>(['"]$MAIN_REGEX['"], )+)(or ['"](?<last>$MAIN_REGEX)['"])?\?"""
            ).map { Regex(it) }
        )

        val ARG_REGEXES = mapOf(
            "SKIP" to listOf(
                """Unknown argument ['"]$MAIN_REGEX['"] on field ['"]$MAIN_REGEX['"]\.""",
                """Unknown argument ['"]$MAIN_REGEX['"] on field ['"]$MAIN_REGEX['"] of type ['"]$MAIN_REGEX['"]\.""",
                """Field ['"]$MAIN_REGEX['"] of type ['"]$MAIN_REGEX['"] must have a selection of subfields\. Did you mean ['"]$MAIN_REGEX( \{ \.\.\. \})?['"]\?""",
                """Field ['"]$MAIN_REGEX['"] argument ['"]$MAIN_REGEX['"] of type ['"]$MAIN_REGEX['"] is $REQUIRED_BUT_NOT_PROVIDED"""
            ).map { Regex(it) },

            "SINGLE_SUGGESTION" to listOf(
                """Unknown argument ['"]$MAIN_REGEX['"] on field ['"]$MAIN_REGEX['"] of type ['"]$MAIN_REGEX['"]\. Did you mean ['"](?<arg>$MAIN_REGEX)['"]\?""",
                """Unknown argument ['"]$MAIN_REGEX['"] on field ['"]$MAIN_REGEX['"]\. Did you mean ['"](?<arg>$MAIN_REGEX)['"]\?"""
            ).map { Regex(it) },

            "DOUBLE_SUGGESTION" to listOf(
                """Unknown argument ['"]$MAIN_REGEX['"] on field ['"]$MAIN_REGEX['"]( of type ['"]$MAIN_REGEX['"])?\. Did you mean ['"](?<first>$MAIN_REGEX)['"] or ['"](?<second>$MAIN_REGEX)['"]\?"""
            ).map { Regex(it) },

            "MULTI_SUGGESTION" to listOf(
                """Unknown argument ['"]$MAIN_REGEX['"] on field ['"]$MAIN_REGEX['"]\. Did you mean (?<multi>(['"]$MAIN_REGEX['"], )+)(or ['"](?<last>$MAIN_REGEX)['"])?\?"""
            ).map { Regex(it) }
        )

        val TYPEREF_REGEXES = mapOf(
            "FIELD" to listOf(
                """Field ['"]$MAIN_REGEX['"] of type ['"](?<typeref>$MAIN_REGEX)['"] must have a selection of subfields\. Did you mean ['"]$MAIN_REGEX( \{ \.\.\. \})?['"]\?""",
                """Field ['"]$MAIN_REGEX['"] must not have a selection since type ['"](?<typeref>$MAIN_REGEX)['"] has no subfields\.""",
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"](?<typeref>$MAIN_REGEX)['"]\.""",
                """Cannot query field ['"]$MAIN_REGEX['"] on type ['"](?<typeref>$MAIN_REGEX)['"]\. Did you mean [^?]+\?""",
                """Field ['"]$MAIN_REGEX['"] of type ['"](?<typeref>$MAIN_REGEX)['"] must not have a sub selection\.""",
                """Field ['"]$MAIN_REGEX['"] of type ['"](?<typeref>$MAIN_REGEX)['"] must have a sub selection\."""
            ).map { Regex(it) },

            "ARG" to listOf(
                """Field ['"]$MAIN_REGEX['"] argument ['"]$MAIN_REGEX['"] of type ['"](?<typeref>$MAIN_REGEX)['"] is $REQUIRED_BUT_NOT_PROVIDED""",
                """Expected type (?<typeref>$MAIN_REGEX), found .+\."""
            ).map { Regex(it) }
        )

        const val WRONG_FIELD_EXAMPLE = "IAmWrongField"

        val WRONG_TYPENAME = listOf(
            """Cannot query field ['"]$WRONG_FIELD_EXAMPLE['"] on type ['"](?<typename>$MAIN_REGEX)['"].""",
            """Field ['"]$MAIN_REGEX['"] must not have a selection since type ['"](?<typename>$MAIN_REGEX)['"] has no subfields.""",
            """Field ['"]$MAIN_REGEX['"] of type ['"](?<typename>$MAIN_REGEX)['"] must not have a sub selection."""
        ).map { Regex(it) }

        val GENERAL_SKIP = listOf(
            """String cannot represent a non string value: .+""",
            """Float cannot represent a non numeric value: .+""",
            """ID cannot represent a non-string and non-integer value: .+""",
            """Enum ['"]$MAIN_REGEX['"] cannot represent non-enum value: .+""",
            """Int cannot represent non-integer value: .+""",
            """Not authorized"""
        ).map { Regex(it) }

        fun getValidFields(errorMessage: String): Set<String> {
            val validFields = mutableSetOf<String>()

            // Skip if it matches a known "skip" pattern
            for (regex in FIELD_REGEXES["SKIP"].orEmpty() + GENERAL_SKIP) {
                if (regex.matches(errorMessage)) {
                    return validFields
                }
            }

            // Try VALID_FIELD patterns
            for (regex in FIELD_REGEXES["VALID_FIELD"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    val field = match.groups["field"]?.value
                    if (field != null) validFields.add(field)
                    return validFields
                }
            }

            // Try SINGLE_SUGGESTION patterns
            for (regex in FIELD_REGEXES["SINGLE_SUGGESTION"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    val field = match.groups["field"]?.value
                    if (field != null) validFields.add(field)
                    return validFields
                }
            }

            // Try DOUBLE_SUGGESTION patterns
            for (regex in FIELD_REGEXES["DOUBLE_SUGGESTION"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    match.groups["one"]?.value?.let { validFields.add(it) }
                    match.groups["two"]?.value?.let { validFields.add(it) }
                    return validFields
                }
            }

            // Try MULTI_SUGGESTION patterns
            for (regex in FIELD_REGEXES["MULTI_SUGGESTION"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    val multi = match.groups["multi"]?.value
                    if (!multi.isNullOrEmpty()) {
                        multi.split(", ").forEach {
                            validFields.add(it.trim('"', '\''))
                        }
                    }
                    match.groups["last"]?.value?.let { validFields.add(it) }
                    return validFields
                }
            }

            Logger.debug("Unknown error message for `valid_field`: '$errorMessage'")
            return validFields
        }

        fun getValidArgs(errorMessage: String): Set<String> {
            val validArgs = mutableSetOf<String>()

            // Skip if it matches a known "skip" pattern
            for (regex in ARG_REGEXES["SKIP"].orEmpty() + GENERAL_SKIP) {
                if (regex.matches(errorMessage)) {
                    return validArgs
                }
            }

            // Try SINGLE_SUGGESTION patterns
            for (regex in ARG_REGEXES["SINGLE_SUGGESTION"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    val field = match.groups["arg"]?.value
                    if (field != null) validArgs.add(field)
                    return validArgs
                }
            }

            // Try DOUBLE_SUGGESTION patterns
            for (regex in ARG_REGEXES["DOUBLE_SUGGESTION"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    match.groups["first"]?.value?.let { validArgs.add(it) }
                    match.groups["second"]?.value?.let { validArgs.add(it) }
                    return validArgs
                }
            }

            // Try MULTI_SUGGESTION patterns
            for (regex in ARG_REGEXES["MULTI_SUGGESTION"].orEmpty()) {
                val match = regex.matchEntire(errorMessage)
                if (match != null) {
                    val multi = match.groups["multi"]?.value
                    if (!multi.isNullOrEmpty()) {
                        multi.split(", ").forEach {
                            validArgs.add(it.trim('"', '\''))
                        }
                    }
                    match.groups["last"]?.value?.let { validArgs.add(it) }
                    return validArgs
                }
            }

            Logger.debug("Unknown error message for `valid_args`: '$errorMessage'")
            return validArgs
        }
    }
}