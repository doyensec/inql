package inql.utils

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.schema.*
import inql.Logger
import inql.scanner.ScanResult


class QueryToRequestConverter(private val scanResults: ScanResult) {
    fun convert(queryNode: String, parentNode: String): String {
        Logger.warning("Query: $queryNode, Parent: $parentNode")
        var q = generateSpecificQuery(scanResults.parsedSchema.schema, queryNode)
        return q;
    }

    fun generateSpecificQuery(
        schema: GraphQLSchema,
        fieldName: String,
        maxDepth: Int = 3 // Default depth limit
    ): String {
        val queryType = schema.queryType
        val targetField = queryType.getFieldDefinition(fieldName)
            ?: throw IllegalArgumentException("Field '$fieldName' not found")

        return buildString {
            append("query GeneratedQuery {\n")
            append("  ${targetField.name}")

            // Add arguments
            if (targetField.arguments.isNotEmpty()) {
                append("(")
                targetField.arguments.joinTo(this, ", ") { arg ->
                    "${arg.name}: ${generateExampleValue(arg.type)}"
                }
                append(")")
            }

            // Add nested fields with depth control
            val selectionSet = getSelectionSet(
                type = targetField.type,
                currentDepth = 0,
                maxDepth = maxDepth
            )

            if (selectionSet.isNotEmpty()) {
                append(" {\n")
                append(selectionSet)
                append("\n  }")
            }
            append("\n}")
        }
    }

    // Generate example values for arguments (including input objects)
    private fun generateExampleValue(type: GraphQLType): String {
        val unwrappedType = unwrapType(type)
        return when (getTypeName(unwrappedType)) {
            "String" -> "\"exampleString\""
            "Int" -> "42"
            "Float" -> "3.14"
            "Boolean" -> "true"
            "ID" -> "\"123\""
            else -> when (unwrappedType) {
                is GraphQLEnumType -> unwrappedType.values.first().name
                is GraphQLInputObjectType -> {
                    // Generate input object fields (e.g., PostFilter)
                    val fields = unwrappedType.fields.joinToString(", ") { field ->
                        "${field.name}: ${generateExampleValue(field.type)}"
                    }
                    "{ $fields }"
                }
                else -> "\"UNKNOWN_TYPE_${unwrappedType}\""
            }

        }
    }

    private fun getSelectionSet(
        type: GraphQLType,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String> = mutableSetOf()
    ): String {
        if (currentDepth >= maxDepth) return "" // Depth limit reached

        val unwrappedType = unwrapType(type)
        return when (unwrappedType) {
            is GraphQLObjectType -> {
                if (visitedTypes.contains(unwrappedType.name)) return ""
                visitedTypes.add(unwrappedType.name)

                unwrappedType.fieldDefinitions.joinToString("\n") { field ->
                    val nestedSelection = getSelectionSet(
                        type = field.type,
                        currentDepth = currentDepth + 1,
                        maxDepth = maxDepth,
                        visitedTypes = visitedTypes.toMutableSet()
                    )

                    val indent = "  ".repeat(currentDepth + 1)
                    buildString {
                        append("$indent${field.name}")
                        if (nestedSelection.isNotEmpty()) {
                            append(" {\n$nestedSelection\n$indent}")
                        }
                    }
                }.also { visitedTypes.remove(unwrappedType.name) }
            }
            else -> ""
        }
    }

    // Unwrap Non-Null/List wrappers
    private fun unwrapType(type: GraphQLType): GraphQLType {
        return when (type) {
            is GraphQLNonNull -> unwrapType(type.wrappedType)
            is GraphQLList -> unwrapType(type.wrappedType)
            else -> type
        }
    }

    fun getTypeName(type: GraphQLType): String {
        return when (type) {
            is GraphQLNonNull -> getTypeName(type.wrappedType) // Unwrap NonNull
            is GraphQLList -> getTypeName(type.wrappedType)    // Unwrap List
            is GraphQLNamedType -> type.name                   // Base type (Object, Scalar, Enum, etc.)
            else -> "UnknownType"
        }
    }
}