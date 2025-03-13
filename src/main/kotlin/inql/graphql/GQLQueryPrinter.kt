package inql.graphql

import graphql.language.*
import graphql.schema.*

class GQLQueryPrinter(val field: GraphQLFieldDefinition, val operationType: GQLSchema.OperationType, val maxDepth: Int = 4, val padSize: Int = 4) {
    companion object {
        private val BUILTIN_SCALARS = setOf("Int", "Float", "String", "Boolean", "ID")
    }

    var _sdl: String? = null

    public fun printSDL(): String {
        if (_sdl == null) {
            val sb = StringBuilder()
            sb.appendLine("${operationType.name.lowercase()} ${field.name} {")
            printSingleField(field, sb, 1, maxDepth, padSize)
            sb.appendLine("}")
            _sdl = sb.toString()
        }
        return _sdl!!;
    }


    /* Field */
    private fun printSingleField(type: GraphQLFieldDefinition, sb: StringBuilder, depth: Int = 1, maxDepth: Int = 4, padSize: Int = 4) {
        val padding = " ".repeat(padSize * depth)
        val descriptionLines = printFieldComment(type)
        val name = type.name
        val args = printArguments(type.arguments)
        val innerType = Utils.unwrapType(type.type)
        val isLeaf = innerType is GraphQLScalarType || innerType is GraphQLEnumType

        // Handle "leaf" field
        if (isLeaf) {
            if (descriptionLines.size == 1) {
                // Leafs can have an "inline" description
                sb.appendLine("$padding$name$args ${descriptionLines[0]}")
                return
            } else {
                sb.appendLinesWithPadding(descriptionLines, padding)
                sb.appendLine("$padding$name$args")
                return
            }
        }

        if (innerType !is GraphQLFieldsContainer && innerType !is GraphQLUnionType) {
            throw NotImplementedError("Error processing type $type, Unknown inner field type: $innerType")
        }

        // Handle object field
        sb.appendLinesWithPadding(descriptionLines, padding)

        // If we reached maxDepth, just print the field commented out and return
        if (depth > maxDepth) {
            sb.appendLine("$padding$name$args # { Truncated by depth limit }")
            return
        }

        // Otherwise open a new block and go deeper
        sb.appendLine("$padding$name$args {")
        when (innerType) {
            is GraphQLFieldsContainer -> {
                for (innerField in innerType.fields.sortedBy { it.name }) {
                    printSingleField(innerField, sb, depth + 1, maxDepth, padSize)
                }
            }

            is GraphQLUnionType -> {
                for (unionInnerType in innerType.types.sortedBy { it.name }) {
                    if (unionInnerType !is GraphQLFieldsContainer) {
                        throw NotImplementedError("Unknown field type: $unionInnerType")
                    }
                    printUnionType(unionInnerType, sb, depth + 1, maxDepth, padSize)
                }
            }

            else -> {
                throw NotImplementedError("Unknown field type: $innerType")
            }
        }
        sb.appendLine("$padding}")
    }

    private fun printUnionType(type: GraphQLFieldsContainer, sb: StringBuilder, depth: Int, maxDepth: Int, padSize: Int) {
        val padding = " ".repeat(padSize * depth)
        sb.appendLine("$padding... on ${type.name} {")
        sb.appendLine("${" ".repeat(padSize * (depth + 1))}__typename")
        for (field in type.fields.sortedBy { it.name }) {
            printSingleField(field, sb, depth + 1, maxDepth, padSize)
        }
        sb.appendLine("$padding}")
    }

    /* Arguments */
    private fun printLiteralValue(value: Value<*>): String {
        return when (value) {
            is StringValue -> "\"${value.value}\""
            is BooleanValue -> "${value.isValue}"
            is EnumValue -> value.name
            is FloatValue -> "${value.value}"
            is IntValue -> "${value.value}"
            is NullValue -> "null"
            is ObjectValue -> "{${value.objectFields.joinToString(", ") { "${it.name}: ${printLiteralValue(it.value)}" }}}"
            is ArrayValue -> "[${value.values.joinToString(", ") { printLiteralValue(it) }}"
            else -> value.toString()
        }
    }

    private fun printArgumentDefaultValue(valueObj: InputValueWithState): String? {
        if (valueObj.isNotSet) {
            return null
        }

        val value = valueObj.value
        if (valueObj.isExternal) {
            return if (value is String) {
                "\"$value\""
            } else {
                value.toString()
            }
        } else if (valueObj.isLiteral && value is Value<*>) {
            return printLiteralValue(value)
        }
        throw NotImplementedError("Value type not recognized")
    }

    private fun printArgument(argument: GraphQLArgument): String {
        val defaultValue = printArgumentDefaultValue(argument.argumentDefaultValue)
        val type = argument.type
        val typeString = if (type is GraphQLNamedType) type.name else type.toString()
        return if (defaultValue != null) {
            "${argument.name}: $typeString = $defaultValue"
        } else {
            "${argument.name}: $typeString"
        }
    }

    private fun printArguments(args: List<GraphQLArgument>): String {
        // In GraphQL all fields can have arguments, even scalars
        if (args.isEmpty()) {
            return ""
        }
        return "(${args.joinToString(", ") { printArgument(it) }})"
    }

    private fun printArgsDescription(args: List<GraphQLArgument>): List<String> {
        return args.filter { it.description != null }.map { "${it.name}: ${it.description}" }
    }

    /* Description */
    private fun getFieldDescription(type: GraphQLFieldDefinition): String? {
        if (type.description != null) {
            return type.description!!
        }

        // Try inner type
        val innerType = Utils.unwrapType(type.type)
        if (innerType is GraphQLNamedType && innerType.description != null) {
            return innerType.description!!
        }
        return null
    }

    private fun printFieldComment(type: GraphQLFieldDefinition): List<String> {
        val description: MutableList<String>
        val innerType = Utils.unwrapType(type.type)

        // Get description
        description = if (innerType is GraphQLScalarType && BUILTIN_SCALARS.contains(innerType.name)) {
            // Only add comments for built-in scalars if the top field is commented
            type.description?.lines()?.toMutableList() ?: mutableListOf()
        } else {
            getFieldDescription(type)?.lines()?.toMutableList() ?: mutableListOf()
        }

        // If Enum type, append valid Enum values
        if (innerType is GraphQLEnumType) {
            if (description.isEmpty() || description[0].isEmpty()) {
                description.add("(enum):")
            } else {
                description[0] = "(enum) ${description[0]}"

                // Add a : at the end if the last char is not a symbol
                if (!setOf('.', '!', '?', ':', ';').contains(description.last().last())) {
                    description.add("${description.removeLast()}:")
                }
            }

            // Append enum values
            description.addAll(innerType.values.map { " - ${it.name} (${it.description})" })
        }

        // Add args description
        val argsDesc = printArgsDescription(type.arguments)
        if (argsDesc.isNotEmpty()) {
            if (description.isNotEmpty() && description.last().isNotEmpty() && !setOf('.', '!', '?', ':', ';').contains(description.last().last())) {
                description.add("${description.removeLast()}:")
            }
            description.addAll(argsDesc.map { " - $it" })
        }

        // Handle empty descriptions
        if (description.size == 1 && description[0].isEmpty()) {
            return emptyList()
        }

        return Utils.formatComment(description)
    }

    private fun StringBuilder.appendLinesWithPadding(strings: List<String>, padding: String) {
        for (string in strings) {
            this.append(padding)
            this.appendLine(string)
        }
    }
}