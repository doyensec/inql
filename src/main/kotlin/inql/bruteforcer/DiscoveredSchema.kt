package inql.bruteforcer

/**
 * Schema facts collected by the bruteforcer. Only proven facts are rendered; details that could not be proven
 * are rendered as an "InQL bruteforcer:" description instead of a guess.
 */
internal class DiscoveredSchema {
    enum class Kind { OBJECT, INTERFACE, UNION, ENUM, INPUT_OBJECT, SCALAR }

    /** A type reference. [printed] carries list/non-null modifiers only when [modifiersKnown]. */
    class TypeRef(val named: String, val printed: String, val modifiersKnown: Boolean)

    class InputValue(val name: String, val type: TypeRef)

    class Field(val name: String, val type: TypeRef) {
        val args = linkedMapOf<String, InputValue>()
    }

    class Type(val name: String) {
        var kind: Kind? = null

        /** Known to be a leaf (scalar or enum) while [kind] is still unknown. */
        var leaf = false
        val fields = linkedMapOf<String, Field>()
        val inputFields = linkedMapOf<String, InputValue>()
        val enumValues = linkedSetOf<String>()
        val possibleTypes = linkedSetOf<String>()
        val notes = linkedSetOf<String>()
    }

    var queryType: String? = null
    var mutationType: String? = null
    var subscriptionType: String? = null
    val types = linkedMapOf<String, Type>()

    fun type(name: String): Type = types.getOrPut(name) { Type(name) }

    fun toSdl(): String = buildString {
        val roots = listOfNotNull(
            queryType?.let { "query: $it" },
            mutationType?.let { "mutation: $it" },
            subscriptionType?.let { "subscription: $it" },
        )
        appendLine("schema { ${roots.joinToString(" ")} }")
        for (t in types.values) {
            if (ErrorEvidence.isBuiltInScalar(t.name)) continue
            appendLine()
            append(render(t))
        }
    }

    private fun render(t: Type): String = buildString {
        val notes = t.notes.toMutableList()
        when (t.kind) {
            Kind.OBJECT, Kind.INTERFACE -> {
                val keyword = if (t.kind == Kind.OBJECT) "type" else "interface"
                if (t.fields.isEmpty()) notes += "no fields discovered"
                description(notes, "")
                append("$keyword ${t.name}${implementsClause(t)} {\n")
                if (t.fields.isEmpty()) append("  _inql_placeholder: String\n")
                t.fields.values.forEach { append(renderField(it)) }
                append("}\n")
            }
            Kind.UNION -> {
                val members = t.possibleTypes.filter { types[it]?.kind == Kind.OBJECT }
                if (members.isEmpty()) {
                    description(notes + "union whose possible types could not be determined", "")
                    append("type ${t.name} {\n  _inql_placeholder: String\n}\n")
                } else {
                    description(notes, "")
                    append("union ${t.name} = ${members.joinToString(" | ")}\n")
                }
            }
            Kind.ENUM -> {
                if (t.enumValues.isEmpty()) notes += "no enum values discovered"
                description(notes, "")
                val values = t.enumValues.ifEmpty { setOf("PLACEHOLDER") }
                append("enum ${t.name} {\n${values.joinToString("") { "  $it\n" }}}\n")
            }
            Kind.INPUT_OBJECT -> {
                if (t.inputFields.isEmpty()) notes += "no input fields discovered"
                description(notes, "")
                append("input ${t.name} {\n")
                if (t.inputFields.isEmpty()) append("  _inql_placeholder: String\n")
                t.inputFields.values.forEach { description(modifierNote(it.type), "  "); append("  ${it.name}: ${it.type.printed}\n") }
                append("}\n")
            }
            Kind.SCALAR -> {
                description(notes, "")
                append("scalar ${t.name}\n")
            }
            null -> if (t.leaf) {
                description(notes + "leaf type that may be an enum or a custom scalar", "")
                append("scalar ${t.name}\n")
            } else {
                description(notes + "no fields discovered; it may also be an interface or a union", "")
                append("type ${t.name} {\n  _inql_placeholder: String\n}\n")
            }
        }
    }

    private fun renderField(f: Field): String = buildString {
        description(modifierNote(f.type) + f.args.values.flatMap { a -> modifierNote(a.type).map { "argument ${a.name}: $it" } }, "  ")
        append("  ${f.name}")
        if (f.args.isNotEmpty()) append(f.args.values.joinToString(", ", "(", ")") { "${it.name}: ${it.type.printed}" })
        append(": ${f.type.printed}\n")
    }

    /** `implements` is only rendered when the object has every interface field with the same type. */
    private fun implementsClause(t: Type): String {
        if (t.kind != Kind.OBJECT) return ""
        val interfaces = types.values.filter { i ->
            i.kind == Kind.INTERFACE && t.name in i.possibleTypes && i.fields.isNotEmpty() &&
                i.fields.values.all { f -> t.fields[f.name]?.type?.printed == f.type.printed && f.args.isEmpty() }
        }
        return if (interfaces.isEmpty()) "" else interfaces.joinToString(" & ", " implements ") { it.name }
    }

    private fun modifierNote(type: TypeRef) = if (type.modifiersKnown) emptyList() else listOf("list/non-null modifiers unknown")

    private fun StringBuilder.description(notes: List<String>, indent: String) {
        if (notes.isEmpty()) return
        append("$indent\"\"\"InQL bruteforcer: ${notes.joinToString("; ")}\"\"\"\n")
    }
}
