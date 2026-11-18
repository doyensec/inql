package inql.bruteforcer

/**
 * Facts extracted from GraphQL validation error messages. Each server family words its errors differently
 * (graphql-js and its ports, graphql-core 2, graphql-java, graphql-ruby, async-graphql, Juniper, gqlgen, ...),
 * so every fact has one pattern per wording. Messages that match nothing produce no evidence.
 */
sealed interface Evidence {
    /** [field] does not exist on [parentType]. [possibleTypes] come from "use an inline fragment on" hints. */
    data class UnknownField(
        val field: String,
        val parentType: String,
        val suggestions: List<String>,
        val possibleTypes: List<String>,
    ) : Evidence

    /** Leaf [field] was given a selection; [type] is its type as printed by the server, null when not printed. */
    data class LeafSelection(val field: String, val type: String?, val isEnum: Boolean) : Evidence

    /** Composite [field] was queried without a selection; [type] is its type as printed by the server. */
    data class MissingSelection(val field: String, val type: String) : Evidence

    /** Fields were selected directly on union [type]. */
    data class UnionSelection(val type: String) : Evidence

    data class UnknownArgument(val argument: String, val field: String?, val suggestions: List<String>) : Evidence

    /** Required [arguments] of [field] were not provided; [type] is set when the server prints it. */
    data class MissingArguments(val field: String?, val arguments: List<String>, val type: String?) : Evidence

    /**
     * A value did not match the expected [type]. [argument] is the argument name when the server prints it,
     * [listElement] is set when the server reports the error for a list element, [kind] when the wording implies it.
     */
    data class WrongValue(
        val argument: String?,
        val type: String?,
        val kind: TypeKind?,
        val listElement: Boolean,
        val value: String?,
    ) : Evidence

    data class UnknownEnumValue(val value: String, val enumType: String?, val suggestions: List<String>) : Evidence

    data class UnknownInputField(val field: String, val inputType: String?, val suggestions: List<String>) : Evidence

    /** Required [fields] of [inputType] were not provided; [type] is set when the server prints it. */
    data class MissingInputFields(val inputType: String?, val fields: List<String>, val type: String?) : Evidence

    /** A value of input field [field] did not match the expected [type]. */
    data class InputFieldValue(val inputType: String?, val field: String, val type: String?) : Evidence

    data class UnknownType(val type: String, val suggestions: List<String>) : Evidence

    /** Fragment on [fragmentType] cannot be spread inside [parentType]. */
    data class InvalidSpread(val parentType: String, val fragmentType: String) : Evidence

    /** The server listed every value of enum [enumType]. */
    data class EnumValues(val enumType: String, val values: List<String>) : Evidence

    /** Variable [variable] was used where a value of [expectedType] (printed with modifiers) is expected. */
    data class VariableMismatch(val variable: String, val expectedType: String) : Evidence

    /** A fragment was conditioned on [type], which is a scalar, enum or input object; null when unnamed. */
    data class NonCompositeFragment(val type: String?) : Evidence
}

enum class TypeKind { SCALAR, ENUM, INPUT_OBJECT }

object ErrorEvidence {
    private const val Q = """["'`]?"""
    private const val N = """([_A-Za-z][_0-9A-Za-z]*)"""
    private const val T = """([_A-Za-z\[][_0-9A-Za-z!\[\]]*)"""
    private val BUILT_IN_SCALARS = setOf("Int", "Float", "String", "Boolean", "ID")

    private val QUOTED_NAME = Regex("""["'`]([_A-Za-z][_0-9A-Za-z]*)["'`]""")
    private val JAVA_PATH = Regex("""@\[(?:[^\]]*/)?([_A-Za-z][_0-9A-Za-z]*)]""")

    private val UNKNOWN_FIELD = listOf(
        Regex("""Cannot query field $Q$N$Q on type $Q$N$Q"""),
        Regex("""Unknown field $Q$N$Q on type $Q$N$Q"""),
        Regex("""Field $Q$N$Q in type $Q$N$Q is undefined"""),
        Regex("""Field $Q$N$Q doesn't exist on type $Q$N$Q"""),
    )
    private val LEAF_SELECTION = listOf(
        Regex("""Field $Q$N$Q must not have a selection since type $Q$T$Q has no subfields""") to false,
        Regex("""Field $Q$N$Q of type $Q$T$Q must not have a sub selection""") to false,
    )
    private val JAVA_LEAF_SELECTION = Regex("""Subselection not allowed on leaf type $Q$T$Q of field $Q$N$Q""")
    private val RUBY_LEAF_SELECTION = Regex("""Selections can't be made on (scalars|enums) \(field $Q$N$Q returns $T but has selections""")
    private val MISSING_SELECTION = listOf(
        Regex("""Field $Q$N$Q of type $Q$T$Q must have a (?:selection of subfields|sub selection)"""),
        Regex("""Field must have selections \(field $Q$N$Q returns $T but has no selections"""),
    )
    private val JAVA_MISSING_SELECTION = Regex("""Subselection required for type $Q$T$Q of field $Q$N$Q""")
    private val UNION_SELECTION = Regex("""Selections can't be made directly on unions \(see selections on $N\)""")

    private val UNKNOWN_ARGUMENT = Regex("""Unknown argument $Q$N$Q on field $Q(?:$N\.)?$N$Q""")
    private val JAVA_UNKNOWN_ARGUMENT = Regex("""Unknown field argument $Q$N$Q""")
    private val RUBY_UNKNOWN_ARGUMENT = Regex("""^Field $Q$N$Q doesn't accept argument $Q$N$Q""")
    private val HASURA_UNKNOWN_ARGUMENT = Regex("""^$Q$N$Q has no argument named $Q$N$Q""")
    private val MISSING_ARGUMENT = Regex("""Field $Q$N$Q argument $Q$N$Q of type $Q$T$Q is required""")
    private val JAVA_MISSING_ARGUMENT = Regex("""Missing field argument $Q$N$Q""")
    private val RUBY_MISSING_ARGUMENTS = Regex("""Field $Q$N$Q is missing required arguments: ([_0-9A-Za-z, ]+)""")

    private val SCALAR_VALUE = Regex("""^(Int|Float|String|Boolean|ID) cannot represent""")
    private val ENUM_VALUE = Regex("""^Enum $Q$N$Q cannot represent non-enum value""")
    private val ENUM_UNKNOWN_VALUE = Regex("""^Value $Q$N$Q does not exist in $Q$N$Q enum""")
    private val EXPECTED_VALUE_OF_TYPE = Regex("""^Expected value of type $Q$T$Q, found""")
    private val ASYNC_EXPECTED_INPUT = Regex("""^Expected input type $Q$T$Q, found""")
    private val ASYNC_INVALID_VALUE = Regex("""^Invalid value for argument $Q([_0-9A-Za-z.]+)$Q, (.*)$""")
    private val LEGACY_INVALID_VALUE = Regex("""^Argument $Q$N$Q has invalid value (.*?)\.?$""")
    private val JAVA_INVALID_VALUE = Regex("""argument '([_0-9A-Za-z.\[\]]+)' with value '(.*?)' (is not a valid|must be an object type|contains a field not in|is missing required fields)(.*)$""")
    private val RUBY_ARGUMENT_VALUE = Regex("""^Argument $Q$N$Q on Field $Q$N$Q has an invalid value \((.*)\)\. Expected type $Q$T$Q""")
    private val RUBY_INPUT_FIELD_VALUE = Regex("""^Argument $Q$N$Q on InputObject $Q$N$Q has an invalid value .*Expected type $Q$T$Q""")
    private val RUBY_INPUT_FIELD_REQUIRED = Regex("""^Argument $Q$N$Q on InputObject $Q$N$Q is required\. Expected type $T""")
    private val RUBY_UNKNOWN_INPUT_FIELD = Regex("""^InputObject $Q$N$Q doesn't accept argument $Q$N$Q""")

    private val UNKNOWN_INPUT_FIELD = Regex("""Field $Q$N$Q is not defined by type $Q$N$Q""")
    private val REQUIRED_INPUT_FIELD = Regex("""Field $Q$N\.$N$Q of required type $Q$T$Q was not provided""")

    private val VARIABLE_MISMATCH = listOf(
        Regex("""Variable $Q\$?$N$Q of type $Q$T$Q used in position expecting type $Q$T$Q"""),
        Regex("""(?:Type|Nullability) mismatch on variable \$$N and argument $N \($T / $T\)"""),
    )

    private val UNKNOWN_TYPE = Regex("""Unknown type $Q$N$Q""")
    private val RUBY_UNKNOWN_TYPE = Regex("""No such type $N, so it can't be a fragment condition""")
    private val INVALID_SPREAD = Regex("""Fragment cannot be spread here as objects of type $Q$N$Q can never be of type $Q$N$Q""")
    private val RUBY_INVALID_SPREAD = Regex("""Fragment on $N can't be spread inside $N""")
    private val NON_COMPOSITE_FRAGMENT = listOf(
        Regex("""Fragment cannot condition (?:on )?non composite type $Q$N$Q"""),
        Regex("""Invalid fragment on type $N \(must be Union, Interface or Object\)"""),
    )

    /** Parses [message]; [path] is Hasura's `extensions.path` (e.g. `$.selectionSet.pastes.args.where.title`). */
    fun parse(message: String, path: String? = null): List<Evidence> {
        val out = mutableListOf<Evidence>()
        val firstLine = message.substringBefore('\n')
        if (path != null) parseHasura(firstLine, path, out)

        for (regex in UNKNOWN_FIELD) {
            val m = regex.find(firstLine) ?: continue
            val tail = firstLine.substring(m.range.last + 1)
            val possibleTypes = tail.substringAfter("inline fragment on", "").let(::quotedNames)
            val suggestions = if (possibleTypes.isEmpty()) suggestionsIn(tail) else emptyList()
            out += Evidence.UnknownField(m.groupValues[1], m.groupValues[2], suggestions, possibleTypes)
        }
        LEAF_SELECTION.forEach { (regex, _) ->
            regex.find(firstLine)?.let { out += Evidence.LeafSelection(it.groupValues[1], it.groupValues[2], false) }
        }
        JAVA_LEAF_SELECTION.find(firstLine)?.let { out += Evidence.LeafSelection(it.groupValues[2], it.groupValues[1], false) }
        RUBY_LEAF_SELECTION.find(firstLine)?.let {
            out += Evidence.LeafSelection(it.groupValues[2], it.groupValues[3], it.groupValues[1] == "enums")
        }
        MISSING_SELECTION.forEach { regex ->
            regex.find(firstLine)?.let { out += Evidence.MissingSelection(it.groupValues[1], it.groupValues[2]) }
        }
        JAVA_MISSING_SELECTION.find(firstLine)?.let { out += Evidence.MissingSelection(it.groupValues[2], it.groupValues[1]) }
        UNION_SELECTION.find(firstLine)?.let { out += Evidence.UnionSelection(it.groupValues[1]) }

        parseArguments(firstLine, message, out)
        parseValues(firstLine, message, out)

        UNKNOWN_TYPE.find(firstLine)?.let {
            out += Evidence.UnknownType(it.groupValues[1], suggestionsIn(firstLine.substring(it.range.last + 1)))
        }
        RUBY_UNKNOWN_TYPE.find(firstLine)?.let {
            out += Evidence.UnknownType(it.groupValues[1], suggestionsIn(firstLine.substring(it.range.last + 1)))
        }
        INVALID_SPREAD.find(firstLine)?.let { out += Evidence.InvalidSpread(it.groupValues[1], it.groupValues[2]) }
        RUBY_INVALID_SPREAD.find(firstLine)?.let { out += Evidence.InvalidSpread(it.groupValues[2], it.groupValues[1]) }
        NON_COMPOSITE_FRAGMENT.forEach { regex -> regex.find(firstLine)?.let { out += Evidence.NonCompositeFragment(it.groupValues[1]) } }
        if (firstLine.contains("Inline fragment type condition is invalid")) out += Evidence.NonCompositeFragment(null)
        VARIABLE_MISMATCH[0].find(firstLine)?.let { out += Evidence.VariableMismatch(it.groupValues[1], it.groupValues[3]) }
        VARIABLE_MISMATCH[1].find(firstLine)?.let { out += Evidence.VariableMismatch(it.groupValues[1], it.groupValues[4]) }
        return out
    }

    private fun parseArguments(line: String, message: String, out: MutableList<Evidence>) {
        val javaField = JAVA_PATH.find(line)?.groupValues?.get(1)
        UNKNOWN_ARGUMENT.find(line)?.let {
            out += Evidence.UnknownArgument(it.groupValues[1], it.groupValues[3], suggestionsIn(line.substring(it.range.last + 1)))
        }
        JAVA_UNKNOWN_ARGUMENT.find(line)?.let { out += Evidence.UnknownArgument(it.groupValues[1], javaField, emptyList()) }
        RUBY_UNKNOWN_ARGUMENT.find(line)?.let {
            out += Evidence.UnknownArgument(it.groupValues[2], it.groupValues[1], suggestionsIn(line.substring(it.range.last + 1)))
        }
        HASURA_UNKNOWN_ARGUMENT.find(line)?.let { out += Evidence.UnknownArgument(it.groupValues[2], it.groupValues[1], emptyList()) }
        MISSING_ARGUMENT.find(line)?.let {
            out += Evidence.MissingArguments(it.groupValues[1], listOf(it.groupValues[2]), it.groupValues[3])
        }
        JAVA_MISSING_ARGUMENT.find(line)?.let { out += Evidence.MissingArguments(javaField, listOf(it.groupValues[1]), null) }
        RUBY_MISSING_ARGUMENTS.find(message)?.let { m ->
            out += Evidence.MissingArguments(m.groupValues[1], m.groupValues[2].split(',').map { it.trim() }.filter { it.isNotEmpty() }, null)
        }
    }

    private fun parseValues(line: String, message: String, out: MutableList<Evidence>) {
        SCALAR_VALUE.find(line)?.let { out += Evidence.WrongValue(null, it.groupValues[1], TypeKind.SCALAR, false, null) }
        ENUM_VALUE.find(line)?.let { out += Evidence.WrongValue(null, it.groupValues[1], TypeKind.ENUM, false, null) }
        ENUM_UNKNOWN_VALUE.find(line)?.let {
            out += Evidence.UnknownEnumValue(it.groupValues[1], it.groupValues[2], suggestionsIn(line.substring(it.range.last + 1)))
            out += Evidence.WrongValue(null, it.groupValues[2], TypeKind.ENUM, false, it.groupValues[1])
        }
        EXPECTED_VALUE_OF_TYPE.find(line)?.let { out += Evidence.WrongValue(null, it.groupValues[1], null, false, null) }
        ASYNC_EXPECTED_INPUT.find(line)?.let { out += Evidence.WrongValue(null, it.groupValues[1], null, false, null) }
        REQUIRED_INPUT_FIELD.find(line)?.let {
            out += Evidence.MissingInputFields(it.groupValues[1], listOf(it.groupValues[2]), it.groupValues[3])
        }
        if (!line.startsWith("InputObject")) {
            UNKNOWN_INPUT_FIELD.find(line)?.let {
                out += Evidence.UnknownInputField(it.groupValues[1], it.groupValues[2], suggestionsIn(line.substring(it.range.last + 1)))
            }
        }
        ASYNC_INVALID_VALUE.find(line)?.let { parseAsyncValue(it.groupValues[1], it.groupValues[2], out) }
        LEGACY_INVALID_VALUE.find(line)?.let { parseLegacyValue(it.groupValues[1], it.groupValues[2], message, out) }
        JAVA_INVALID_VALUE.find(line)?.let { parseJavaValue(it, out) }
        RUBY_ARGUMENT_VALUE.find(line)?.let {
            out += Evidence.WrongValue(it.groupValues[1], it.groupValues[4], null, false, it.groupValues[3])
        }
        RUBY_INPUT_FIELD_VALUE.find(line)?.let { out += Evidence.InputFieldValue(it.groupValues[2], it.groupValues[1], it.groupValues[3]) }
        RUBY_INPUT_FIELD_REQUIRED.find(line)?.let {
            out += Evidence.MissingInputFields(it.groupValues[2], listOf(it.groupValues[1]), it.groupValues[3])
        }
        RUBY_UNKNOWN_INPUT_FIELD.find(line)?.let {
            out += Evidence.UnknownInputField(it.groupValues[2], it.groupValues[1], suggestionsIn(line.substring(it.range.last + 1)))
        }
    }

    /** async-graphql and Juniper: `Invalid value for argument "path", <reason>`. */
    private fun parseAsyncValue(path: String, reason: String, out: MutableList<Evidence>) {
        val segments = path.split('.')
        val argument = segments.first()
        val listElement = segments.size > 1 && segments.last().all { it.isDigit() }
        val inputField = segments.drop(1).lastOrNull { !it.all(Char::isDigit) }

        Regex("""^expected type $Q$T$Q""").find(reason)?.let {
            if (inputField != null) out += Evidence.InputFieldValue(null, inputField, it.groupValues[1])
            else out += Evidence.WrongValue(argument, it.groupValues[1], null, listElement, null)
        }
        Regex("""^enumeration type $Q$N$Q does not contain the value $Q$N$Q""").find(reason)?.let {
            out += Evidence.UnknownEnumValue(it.groupValues[2], it.groupValues[1], emptyList())
            out += Evidence.WrongValue(argument, it.groupValues[1], TypeKind.ENUM, false, it.groupValues[2])
        }
        Regex("""^unknown field $Q$N$Q of type $Q$N$Q""").find(reason)?.let {
            out += Evidence.UnknownInputField(it.groupValues[1], it.groupValues[2], emptyList())
        }
        Regex("""^field $Q$N$Q of type $Q$T$Q is required""").find(reason)?.let {
            out += Evidence.MissingInputFields(null, listOf(it.groupValues[1]), it.groupValues[2])
        }
        Regex("""^reason: Invalid value "(.*)" for (type|enum) $Q$N$Q$""").find(reason)?.let {
            val kind = if (it.groupValues[2] == "enum") TypeKind.ENUM else null
            out += Evidence.WrongValue(argument, it.groupValues[3], kind, false, it.groupValues[1].trim('"'))
        }
        Regex("""^reason: Field $Q$N$Q does not exist on type $Q$N$Q""").find(reason)?.let {
            out += Evidence.UnknownInputField(it.groupValues[1], it.groupValues[2], emptyList())
        }
        Regex("""^reason: Error on $Q$N$Q field $Q$N$Q: Invalid value .* for (?:type|enum) $Q$N$Q""").find(reason)?.let {
            out += Evidence.InputFieldValue(it.groupValues[1], it.groupValues[2], it.groupValues[3])
        }
        Regex("""^reason: $Q$N$Q is missing fields: (.*)$""").find(reason)?.let {
            out += Evidence.MissingInputFields(it.groupValues[1], quotedNames(it.groupValues[2]), null)
        }
    }

    /**
     * graphql-core 2 and graphql-go: a first line naming the argument followed by `Expected ...` lines, prefixed with
     * `In field "f": ` once per nesting level and `In element #n: ` for list elements.
     */
    private fun parseLegacyValue(argument: String, value: String, message: String, out: MutableList<Evidence>) {
        val prefix = Regex("""^(?:In field $Q$N$Q|In element #\d+): """)
        for (line in message.lines().drop(1)) {
            var rest = line
            var field: String? = null
            var listElement = false
            while (true) {
                val m = prefix.find(rest) ?: break
                if (m.groupValues[1].isNotEmpty()) field = m.groupValues[1] else listElement = true
                rest = rest.substring(m.range.last + 1)
            }
            Regex("""^Expected type $Q$T$Q, found""").find(rest)?.let {
                out += if (field != null) Evidence.InputFieldValue(null, field, it.groupValues[1])
                else Evidence.WrongValue(argument, it.groupValues[1], null, listElement, value)
            }
            Regex("""^Expected $Q$N$Q, found not an object""").find(rest)?.let {
                out += if (field != null) Evidence.InputFieldValue(null, field, it.groupValues[1])
                else Evidence.WrongValue(argument, it.groupValues[1], TypeKind.INPUT_OBJECT, false, null)
            }
            if (field != null && rest.startsWith("Unknown field")) out += Evidence.UnknownInputField(field, null, emptyList())
            Regex("""^Expected $Q$T$Q, found null""").find(rest)?.let {
                if (field != null) out += Evidence.MissingInputFields(null, listOf(field), it.groupValues[1])
            }
        }
    }

    private fun parseJavaValue(m: MatchResult, out: MutableList<Evidence>) {
        val path = m.groupValues[1]
        val argument = path.substringBefore('.').substringBefore('[')
        val listElement = path.endsWith("]")
        val inputField = path.split('.').drop(1).lastOrNull()?.substringBefore('[')
        val rest = m.groupValues[4]
        val value = Regex("""EnumValue\{name='([_0-9A-Za-z]+)'}""").find(m.groupValues[2])?.groupValues?.get(1)
        when (m.groupValues[3]) {
            "is not a valid" -> {
                val type = Regex("""^ $Q$T$Q""").find(rest)?.groupValues?.get(1)
                val isEnum = rest.contains("allowable values for enum")
                if (isEnum && value != null) out += Evidence.UnknownEnumValue(value, type, emptyList())
                if (inputField != null) out += Evidence.InputFieldValue(null, inputField, type)
                else out += Evidence.WrongValue(argument, type, if (isEnum) TypeKind.ENUM else null, listElement, value)
            }
            "must be an object type" -> if (inputField == null) {
                out += Evidence.WrongValue(argument, null, TypeKind.INPUT_OBJECT, listElement, null)
            }
            "contains a field not in" -> Regex("""^ $Q$N$Q: $Q$N$Q""").find(rest)?.let {
                out += Evidence.UnknownInputField(it.groupValues[2], it.groupValues[1], emptyList())
            }
            "is missing required fields" -> out += Evidence.MissingInputFields(
                null,
                rest.substringAfter('[').substringBefore(']').split(',').map { it.trim() }.filter { it.isNotEmpty() },
                null,
            )
        }
    }

    /** Hasura reports one error per request and locates it with a JSON path instead of naming everything. */
    private fun parseHasura(line: String, path: String, out: MutableList<Evidence>) {
        val segments = path.removePrefix("$").split('.').filter { it.isNotEmpty() && it != "selectionSet" }.map { it.substringBefore('[') }
        val argsAt = segments.indexOf("args")
        val name = segments.lastOrNull()
        Regex("""^field $Q$N$Q not found in type: $Q$N$Q""").find(line)?.let {
            out += if (argsAt >= 0) Evidence.UnknownInputField(it.groupValues[1], it.groupValues[2], emptyList())
            else Evidence.UnknownField(it.groupValues[1], it.groupValues[2], emptyList(), emptyList())
        }
        Regex("""^missing selection set for $Q$N$Q""").find(line)?.let { if (name != null) out += Evidence.MissingSelection(name, it.groupValues[1]) }
        if (line.startsWith("unexpected subselection set for non-object field") && name != null) out += Evidence.LeafSelection(name, null, false)
        Regex("""^missing required field $Q$N$Q""").find(line)?.let {
            if (argsAt == segments.size - 2) out += Evidence.MissingArguments(segments.getOrNull(argsAt - 1), listOf(it.groupValues[1]), null)
            else if (argsAt >= 0) out += Evidence.MissingInputFields(null, listOf(it.groupValues[1]), null)
        }
        Regex("""^variable $Q$N$Q is declared as $Q$T$Q, but used where $Q$T$Q is expected""").find(line)?.let {
            out += Evidence.VariableMismatch(it.groupValues[1], it.groupValues[3])
        }
        Regex("""^expected (.*) for type $Q$N$Q, but found (.*)$""").find(line)?.let {
            val expected = it.groupValues[1]
            val type = it.groupValues[2]
            val kind = when {
                expected.startsWith("an object") -> TypeKind.INPUT_OBJECT
                expected.startsWith("an enum value") || expected.startsWith("one of the values") -> TypeKind.ENUM
                else -> null
            }
            if (expected.startsWith("one of the values")) out += Evidence.EnumValues(type, quotedNames(expected))
            val inputField = if (argsAt >= 0 && argsAt < segments.size - 2) name else null
            out += if (inputField != null) Evidence.InputFieldValue(null, inputField, type)
            else Evidence.WrongValue(segments.getOrNull(argsAt + 1), type, kind, false, null)
        }
    }

    private fun suggestionsIn(tail: String): List<String> {
        val idx = listOf("Did you mean", "Perhaps you meant").map { tail.indexOf(it) }.filter { it >= 0 }.minOrNull() ?: return emptyList()
        val text = tail.substring(idx)
        if (text.contains("inline fragment on") || text.contains("{ ... }")) return emptyList()
        return quotedNames(text.removePrefix("Did you mean the enum value"))
    }

    private fun quotedNames(text: String): List<String> = QUOTED_NAME.findAll(text).map { it.groupValues[1] }.toList()

    fun isBuiltInScalar(name: String) = name in BUILT_IN_SCALARS

    /** Names (fields, arguments, values) that an evidence item is about. */
    fun mentions(e: Evidence): List<String> = when (e) {
        is Evidence.UnknownField -> listOf(e.field)
        is Evidence.LeafSelection -> listOf(e.field)
        is Evidence.MissingSelection -> listOf(e.field)
        is Evidence.UnknownArgument -> listOf(e.argument)
        is Evidence.WrongValue -> listOfNotNull(e.argument, e.value)
        is Evidence.UnknownEnumValue -> listOf(e.value)
        is Evidence.UnknownInputField -> listOf(e.field)
        is Evidence.InputFieldValue -> listOf(e.field)
        is Evidence.UnknownType -> listOf(e.type)
        is Evidence.InvalidSpread -> listOf(e.fragmentType)
        else -> emptyList()
    }
}
