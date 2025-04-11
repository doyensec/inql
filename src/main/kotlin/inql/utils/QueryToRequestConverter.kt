package inql.utils

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.schema.*
import inql.Logger
import inql.scanner.ScanResult

data class QueryWithVariables(
    val query: String,
    val variables: Map<String, Any>
)

class QueryToRequestConverter(private val scanResults: ScanResult) {
    fun convert(fieldName: String, operationType: String, maxDepth: Int): String {
        val tmpOperationType = when (operationType.lowercase()) {
            "queries" -> "query"
            "mutations" -> "mutation"
            else -> throw IllegalArgumentException("Unsupported operation: $operationType")
        }

        val queryWithVars = generateOperation(
            schema = scanResults.parsedSchema.schema,
            operationType = tmpOperationType,
            fieldName = fieldName,
            maxDepth = maxDepth
        )
        return formatToJson(queryWithVars)
    }

    private fun generateOperation(
        schema: GraphQLSchema,
        operationType: String,
        fieldName: String,
        arguments: Map<String, Any> = emptyMap(),
        maxDepth: Int = 3
    ): QueryWithVariables {
        val rootType = when (operationType.lowercase()) {
            "query" -> schema.queryType
            "mutation" -> schema.mutationType
                ?: throw IllegalArgumentException("Schema does not support mutations")
            else -> throw IllegalArgumentException("Unsupported operation: $operationType")
        }

        val targetField = rootType.getFieldDefinition(fieldName)
            ?: throw IllegalArgumentException("Field '$fieldName' not found in $operationType type")

        val variablesMap = mutableMapOf<String, Any>()
        val variableDefinitions = mutableListOf<String>()
        val nestedVarCounter = mutableListOf(0)

        // Process root arguments first
        targetField.arguments.forEach { arg ->
            val argName = arg.name
            val varType = getVariableType(arg.type)
            variableDefinitions.add("$$argName: $varType")
            val value = arguments[argName] ?: generateExampleValue(arg.type, 0, maxDepth)
            if (value != null) {
                variablesMap[argName] = value
            }
        }

        // Process selection set to collect NESTED variables BEFORE building query string
        val selectionSet = getSelectionSet(
            type = targetField.type,
            currentDepth = 0,
            maxDepth = maxDepth,
            visitedTypes = mutableSetOf(),
            variablesMap = variablesMap,
            variableDefinitions = variableDefinitions,
            nestedVarCounter = nestedVarCounter
        )

        val query = buildString {
            append("$operationType GeneratedOperation")
            if (variableDefinitions.isNotEmpty()) {
                append("(")
                append(variableDefinitions.joinToString(", "))
                append(")")
            }
            append(" {\n")
            append("  $fieldName")

            // Root arguments
            if (targetField.arguments.isNotEmpty()) {
                append("(")
                targetField.arguments.joinTo(this, ", ") { arg ->
                    "${arg.name}: $${arg.name}"
                }
                append(")")
            }

            // Selection set
            if (selectionSet.isNotEmpty()) {
                append(" {\n")
                append(selectionSet)
                append("\n  }")
            }
            append("\n}")
        }

        return QueryWithVariables(query, variablesMap)
    }


    private fun getSelectionSet(
        type: GraphQLType,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String> = mutableSetOf(),
        variablesMap: MutableMap<String, Any>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>
    ): String {
        if (currentDepth >= maxDepth) return ""

        return when (val unwrappedType = unwrapType(type)) {
            is GraphQLObjectType -> handleObjectType(unwrappedType, currentDepth, maxDepth, visitedTypes, variablesMap, variableDefinitions, nestedVarCounter)
            is GraphQLInterfaceType -> handleObjectType(unwrappedType, currentDepth, maxDepth, visitedTypes, variablesMap, variableDefinitions, nestedVarCounter)
            is GraphQLUnionType -> handleUnionType(unwrappedType, currentDepth, maxDepth, visitedTypes, variablesMap, variableDefinitions, nestedVarCounter)
            else -> ""
        }
    }


    private fun handleObjectType(
        type: GraphQLFieldsContainer,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String>,
        variablesMap: MutableMap<String, Any>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>
    ): String {
        if (visitedTypes.contains(type.name)) return ""
        visitedTypes.add(type.name)

        val fields = type.fieldDefinitions
            .filterNot { it.isDeprecated }
            .joinToString("\n") { field ->
                val fieldType = unwrapType(field.type)
                val nextDepth = currentDepth + 1

                // First determine if we should include this field
                val includeField = when {
                    isScalarOrEnum(fieldType) -> true
                    fieldType is GraphQLFieldsContainer && nextDepth < maxDepth -> true
                    else -> false
                }

                if (!includeField) {
                    return@joinToString ""
                }

                // Process arguments ONLY if field is included
                val args = processFieldArguments(
                    field = field,
                    currentDepth = nextDepth,
                    maxDepth = maxDepth,
                    variablesMap = variablesMap,
                    variableDefinitions = variableDefinitions,
                    nestedVarCounter = nestedVarCounter
                )

                // Build field string
                when {
                    isScalarOrEnum(fieldType) -> {
                        "  ".repeat(nextDepth) + field.name + args
                    }
                    fieldType is GraphQLFieldsContainer -> {
                        val nested = getSelectionSet(
                            type = field.type,
                            currentDepth = nextDepth,
                            maxDepth = maxDepth,
                            visitedTypes = visitedTypes.toMutableSet(),
                            variablesMap = variablesMap,
                            variableDefinitions = variableDefinitions,
                            nestedVarCounter = nestedVarCounter
                        )
                        if (nested.isNotEmpty()) {
                            """
                        |${"  ".repeat(nextDepth)}${field.name}$args {
                        |$nested
                        |${"  ".repeat(nextDepth)}}
                        """.trimMargin()
                        } else {
                            "  ".repeat(nextDepth) + "${field.name}$args { __typename }"
                        }
                    }
                    else -> ""
                }
            }.trim()

        val finalFields = if (fields.isEmpty()) {
            "  ".repeat(currentDepth + 1) + "__typename"
        } else {
            fields
        }

        visitedTypes.remove(type.name)
        return finalFields
    }

    // Modified processFieldArguments to skip null values
    private fun processFieldArguments(
        field: GraphQLFieldDefinition,
        currentDepth: Int,
        maxDepth: Int,
        variablesMap: MutableMap<String, Any>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>
    ): String {
        if (field.arguments.isEmpty()) return ""

        val argsList = mutableListOf<String>()

        field.arguments.forEach { arg ->
            generateExampleValue(arg.type, currentDepth, maxDepth)?.let { exampleValue ->
                val varName = "${field.name}_${arg.name}_${nestedVarCounter[0]++}"
                val varType = getVariableType(arg.type)

                // Only add if value is actually usable
                variableDefinitions.add("$$varName: $varType")
                variablesMap[varName] = exampleValue
                argsList.add("${arg.name}: $${varName}")
            }
        }

        return if (argsList.isNotEmpty()) "(${argsList.joinToString(", ")})" else ""
    }


    // Fixed handleUnionType call
    private fun handleUnionType(
        type: GraphQLUnionType,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String>,
        variablesMap: MutableMap<String, Any>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>
    ): String {
        val selections = type.types.joinToString("\n") { possibleType ->
            getSelectionSet(
                type = possibleType,
                currentDepth = currentDepth,
                maxDepth = maxDepth,
                visitedTypes = visitedTypes,
                variablesMap = variablesMap,
                variableDefinitions = variableDefinitions,
                nestedVarCounter = nestedVarCounter
            )
        }

        return if (selections.isEmpty()) {
            "  ".repeat(currentDepth + 1) + "__typename"
        } else {
            selections
        }
    }

    private fun unwrapType(type: GraphQLType): GraphQLType = when (type) {
        is GraphQLNonNull -> unwrapType(type.wrappedType)
        is GraphQLList -> unwrapType(type.wrappedType)
        else -> type
    }

    private fun isScalarOrEnum(type: GraphQLType): Boolean {
        val unwrapped = unwrapType(type)
        return unwrapped is GraphQLScalarType || unwrapped is GraphQLEnumType
    }

    private fun generateExampleValue(
        type: GraphQLType,
        currentDepth: Int = 0,
        maxDepth: Int = 3
    ): Any? {
        if (currentDepth > maxDepth) {
            return null
        }

        val unwrappedType = unwrapType(type)
        return when (getTypeName(unwrappedType)) {
            "String" -> "exampleString"
            "Int" -> 42
            "Float" -> 3.14
            "Boolean" -> true
            "ID" -> "123"
            else -> when (unwrappedType) {
                is GraphQLEnumType -> unwrappedType.values.first().name
                is GraphQLInputObjectType -> {
                    val fields = unwrappedType.fields
                        .mapNotNull { field ->
                            generateExampleValue(field.type, currentDepth + 1, maxDepth)
                                ?.let { field.name to it }
                        }
                        .toMap()

                    fields.ifEmpty { null }
                }
                else -> null
            }
        }
    }

    private fun getVariableType(type: GraphQLType): String {
        return when (type) {
            is GraphQLNonNull -> "${getVariableType(type.wrappedType)}!"
            is GraphQLList -> "[${getVariableType(type.wrappedType)}]"
            is GraphQLScalarType -> type.name
            is GraphQLEnumType -> type.name
            is GraphQLInputObjectType -> type.name
            else -> "UNKNOWN"
        }
    }

    private fun formatToJson(queryWithVars: QueryWithVariables): String {
        val escapedQuery = escapeJson(queryWithVars.query)
        val variablesJson = formatVariablesToJson(queryWithVars.variables)
        return """{
            |  "query": $escapedQuery,
            |  "variables": $variablesJson
            |}""".trimMargin().replace("\n", "\n  ")
    }

    private fun escapeJson(value: String): String {
        return "\"${value.replace("\n", "\\n").replace("\"", "\\\"")}\""
    }

    private fun getTypeName(type: GraphQLType): String {
        return when (type) {
            is GraphQLNonNull -> getTypeName(type.wrappedType)
            is GraphQLList -> getTypeName(type.wrappedType)
            is GraphQLNamedType -> type.name
            else -> "UnknownType"
        }
    }

    private fun formatVariablesToJson(value: Any): String {
        return when (value) {
            is String -> "\"${value.replace("\"", "\\\"")}\""
            is Number -> value.toString()
            is Boolean -> value.toString()
            is Map<*, *> -> {
                val entries = (value as Map<*, *>).entries.joinToString(", ") { (k, v) ->
                    "\"$k\": ${formatVariablesToJson(v!!)}"
                }
                "{$entries}"
            }
            is List<*> -> {
                val items = value.joinToString(", ") { item ->
                    formatVariablesToJson(item!!)
                }
                "[$items]"
            }
            else -> "\"${value.toString().replace("\"", "\\\"")}\""
        }
    }

}
