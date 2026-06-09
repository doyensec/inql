package inql.utils

import graphql.schema.*
import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.scanners.CycleResult
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

    /**
     * Builds a JSON HTTP body (query + variables) that walks [cycle] along the schema, for Repeater / clipboard.
     */
    fun buildCyclePocJson(cycle: CycleResult): String {
        val schema = scanResults.parsedSchema.schema
        val config = Config.getInstance()
        val argDepth = config.getInt("codegen.depth")!!
        val cycleRepetitions = config.getInt("report.cycles.poc.repetitions")!!.coerceIn(1, 500)

        val rootType = when (cycle.operationType) {
            GQLSchema.OperationType.QUERY -> schema.queryType
            GQLSchema.OperationType.MUTATION -> schema.mutationType
                ?: throw IllegalArgumentException("Schema does not support mutations")
            GQLSchema.OperationType.SUBSCRIPTION -> schema.subscriptionType
                ?: throw IllegalArgumentException("Schema does not support subscriptions")
        }

        val path = expandCyclePathForPoc(
            rootType = rootType,
            pathFieldNames = cycle.pathFieldNames,
            cycleRepeatStartIndex = cycle.cycleRepeatStartIndex,
            cycleRepetitions = cycleRepetitions,
        )
        if (path.isEmpty()) {
            throw IllegalArgumentException(
                "Could not build a schema-valid cycle PoC path from this detection result (try another cycle or check the schema).",
            )
        }

        val variablesMap = mutableMapOf<String, Any>()
        val variableDefinitions = mutableListOf<String>()
        val nestedVarCounter = mutableListOf(0)

        val inner = buildCyclePathSelection(
            container = rootType,
            path = path,
            pathIndex = 0,
            baseIndent = 1,
            variablesMap = variablesMap,
            variableDefinitions = variableDefinitions,
            nestedVarCounter = nestedVarCounter,
            maxDepth = argDepth,
        )

        val opKeyword = when (cycle.operationType) {
            GQLSchema.OperationType.QUERY -> "query"
            GQLSchema.OperationType.MUTATION -> "mutation"
            GQLSchema.OperationType.SUBSCRIPTION -> "subscription"
        }

        val query = buildString {
            append("$opKeyword CyclePoc")
            if (variableDefinitions.isNotEmpty()) {
                append("(")
                append(variableDefinitions.joinToString(", "))
                append(")")
            }
            append(" {\n")
            append(inner)
            append("}")
        }

        return formatToJson(QueryWithVariables(query, variablesMap))
    }

    /**
     * Root [prefix] once, then [cycleRepetitions] full passes of the loop body ([repeatUnit]).
     * Long cycles have a longer [repeatUnit] per repetition; the setting controls laps, not total field count.
     *
     * The scanner stores field *names* only; the closing step often repeats the same (name, target type) pair as an
     * earlier vertex, so name-based rules are unreliable. We pick prefix + loop by trying candidates and accepting
     * the first that [cyclePathValidOnSchema] validates on [rootType] (longer loop first, then without last field).
     */
    private fun expandCyclePathForPoc(
        rootType: GraphQLFieldsContainer,
        pathFieldNames: List<String>,
        cycleRepeatStartIndex: Int,
        cycleRepetitions: Int,
    ): List<String> {
        if (pathFieldNames.isEmpty() || cycleRepetitions < 1) return emptyList()
        val path = pathFieldNames
        val start = cycleRepeatStartIndex.coerceIn(0, path.lastIndex)

        if (path.size == 1) {
            val once = listOf(path[0])
            return if (cyclePathValidOnSchema(rootType, once)) once else emptyList()
        }

        val candidates = mutableListOf<Pair<List<String>, List<String>>>()
        if (start == 0) {
            val prefix = listOf(path[0])
            if (path.size >= 2) {
                candidates.add(prefix to path.subList(1, path.size))
                if (path.size >= 3) {
                    candidates.add(prefix to path.subList(1, path.size - 1))
                }
            }
        } else {
            val prefix = path.take(start)
            candidates.add(prefix to path.subList(start, path.size))
            if (path.size > start + 1) {
                candidates.add(prefix to path.subList(start, path.size - 1))
            }
        }

        for ((prefix, repeatUnit) in candidates.distinct()) {
            if (repeatUnit.isEmpty()) continue
            val expanded = buildList {
                addAll(prefix)
                repeat(cycleRepetitions) { addAll(repeatUnit) }
            }
            if (cyclePathValidOnSchema(rootType, expanded)) {
                val maxFields = 2500
                return if (expanded.size > maxFields) expanded.take(maxFields) else expanded
            }
        }

        return emptyList()
    }

    /** Whether [path] can be walked from [root] with the same container rules as [buildCyclePathSelection]. */
    private fun cyclePathValidOnSchema(root: GraphQLFieldsContainer, path: List<String>): Boolean {
        if (path.isEmpty()) return false
        var container: GraphQLFieldsContainer? = root
        for ((i, name) in path.withIndex()) {
            val c = container ?: return false
            val field = c.getFieldDefinition(name) ?: return false
            val next = cycleFieldsContainer(field.type)
            val isLast = i == path.lastIndex
            if (!isLast && next == null) return false
            container = next
        }
        return true
    }

    private fun cycleFieldsContainer(type: GraphQLType): GraphQLFieldsContainer? {
        val u = unwrapType(type)
        return when (u) {
            is GraphQLObjectType -> u
            is GraphQLInterfaceType -> u
            is GraphQLUnionType -> u.types.firstOrNull() as? GraphQLObjectType
            else -> null
        }
    }

    private fun buildCyclePathSelection(
        container: GraphQLFieldsContainer,
        path: List<String>,
        pathIndex: Int,
        baseIndent: Int,
        variablesMap: MutableMap<String, Any>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
        maxDepth: Int,
    ): String {
        if (pathIndex >= path.size) return ""

        val fieldName = path[pathIndex]
        val field = container.getFieldDefinition(fieldName)
            ?: throw IllegalArgumentException("Field '$fieldName' not found on type '${container.name}'")

        val args = processFieldArguments(
            field,
            pathIndex + 1,
            maxDepth,
            variablesMap,
            variableDefinitions,
            nestedVarCounter,
        )

        val indent = "  ".repeat(baseIndent)
        val isLast = pathIndex == path.lastIndex
        val unwrapped = unwrapType(field.type)

        return buildString {
            append(indent).append(fieldName).append(args)
            if (isLast) {
                val leafContainer = cycleFieldsContainer(field.type)
                if (leafContainer != null) {
                    append(" {\n")
                    append("  ".repeat(baseIndent + 1)).append("__typename\n")
                    append(indent).append("}")
                }
            } else {
                val next = cycleFieldsContainer(field.type)
                    ?: throw IllegalArgumentException("Cannot traverse field '$fieldName' for cycle PoC (non-composite type)")
                append(" {\n")
                append(
                    buildCyclePathSelection(
                        container = next,
                        path = path,
                        pathIndex = pathIndex + 1,
                        baseIndent = baseIndent + 1,
                        variablesMap = variablesMap,
                        variableDefinitions = variableDefinitions,
                        nestedVarCounter = nestedVarCounter,
                        maxDepth = maxDepth,
                    ),
                )
                append("\n").append(indent).append("}")
            }
            if (isLast) append("\n")
        }
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


    private fun handleUnionType(
        type: GraphQLUnionType,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String>,
        variablesMap: MutableMap<String, Any>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>
    ): String {
        val fragmentDepth = currentDepth + 1
        val selections = type.types.mapNotNull { possibleType ->
            val member = possibleType as? GraphQLObjectType ?: return@mapNotNull null
            val nested = getSelectionSet(
                type = member,
                currentDepth = fragmentDepth + 1,
                maxDepth = maxDepth,
                visitedTypes = visitedTypes.toMutableSet(),
                variablesMap = variablesMap,
                variableDefinitions = variableDefinitions,
                nestedVarCounter = nestedVarCounter,
            )
            if (nested.isEmpty()) return@mapNotNull null
            """
            |${"  ".repeat(fragmentDepth)}... on ${member.name} {
            |$nested
            |${"  ".repeat(fragmentDepth)}}
            """.trimMargin()
        }.joinToString("\n")

        return if (selections.isEmpty()) {
            "  ".repeat(fragmentDepth) + "__typename"
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
                val entries = value.entries.joinToString(", ") { (k, v) ->
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
