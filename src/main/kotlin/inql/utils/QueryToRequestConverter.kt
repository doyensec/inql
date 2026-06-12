package inql.utils

import graphql.schema.*
import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.Utils
import inql.graphql.scanners.CycleResult
import inql.scanner.ScanResult
import inql.schema.corrections.InputEnumTypeMatching

data class QueryWithVariables(
    val query: String,
    val variables: Map<String, Any?>,
)

private data class InputFieldContext(
    val inputTypeName: String,
    val fieldName: String,
)

private fun isSchemaPlaceholderField(fieldName: String): Boolean {
    return fieldName == "_inql_placeholder" || fieldName == "PLACEHOLDER"
}

class QueryToRequestConverter(private val scanResults: ScanResult) {
    fun convert(fieldName: String, operationType: String, maxDepth: Int): String {
        val tmpOperationType = when (operationType.lowercase()) {
            "queries" -> "query"
            "mutations" -> "mutation"
            else -> throw IllegalArgumentException("Unsupported operation: $operationType")
        }

        val queryWithVars = generateOperation(
            schema = scanResults.effectiveGraphQLSchema(),
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
        val schema = scanResults.effectiveGraphQLSchema()
        val config = Config.getInstance()
        val argDepth = config.codegenDepth()
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

        val variablesMap = mutableMapOf<String, Any?>()
        val variableDefinitions = mutableListOf<String>()
        val nestedVarCounter = mutableListOf(0)

        val inner = buildCyclePathSelection(
            schema = schema,
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
        val u = Utils.unwrapType(type)
        return when (u) {
            is GraphQLObjectType -> u
            is GraphQLInterfaceType -> u
            is GraphQLUnionType -> null
            else -> null
        }
    }

    private fun buildCyclePathSelection(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
        path: List<String>,
        pathIndex: Int,
        baseIndent: Int,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
        maxDepth: Int,
    ): String {
        if (pathIndex >= path.size) return ""

        val fieldName = path[pathIndex]
        val field = container.getFieldDefinition(fieldName)
            ?: throw IllegalArgumentException("Field '$fieldName' not found on type '${container.name}'")

        val args = processFieldArguments(
            schema = schema,
            field = field,
            currentDepth = pathIndex + 1,
            maxDepth = maxDepth,
            variablesMap = variablesMap,
            variableDefinitions = variableDefinitions,
            nestedVarCounter = nestedVarCounter,
        )

        val indent = "  ".repeat(baseIndent)
        val isLast = pathIndex == path.lastIndex
        val unwrapped = Utils.unwrapType(field.type)

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
                        schema = schema,
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

        val variablesMap = mutableMapOf<String, Any?>()
        val variableDefinitions = mutableListOf<String>()
        val nestedVarCounter = mutableListOf(0)

        // Root variables only when values can be built from known schema input types.
        val argValueDepth = maxDepth + 3
        val rootArgs = mutableListOf<GraphQLArgument>()
        targetField.arguments.forEach { arg ->
            val inputContext = InputFieldContext(
                inputTypeName = fieldName,
                fieldName = arg.name,
            )
            val value = buildRootArgumentValue(
                schema = schema,
                type = arg.type,
                explicit = arguments[arg.name],
                argValueDepth = argValueDepth,
            )
                ?: requiredArgumentFallback(schema, arg.type, inputContext)
                ?: permissiveArgumentFallback(schema, arg.type, inputContext)
            if (value == null) return@forEach
            val varType = getVariableType(schema, arg.type)
            variableDefinitions.add("$${arg.name}: $varType")
            variablesMap[arg.name] = value
            rootArgs.add(arg)
        }

        val selectionSet = getSelectionSet(
            schema = schema,
            type = targetField.type,
            currentDepth = 1,
            maxDepth = maxDepth,
            visitedTypes = mutableSetOf(),
            variablesMap = variablesMap,
            variableDefinitions = variableDefinitions,
            nestedVarCounter = nestedVarCounter,
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

            if (rootArgs.isNotEmpty()) {
                append("(")
                rootArgs.joinTo(this, ", ") { arg ->
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

    private fun buildRootArgumentValue(
        schema: GraphQLSchema,
        type: GraphQLType,
        explicit: Any?,
        argValueDepth: Int,
    ): Any? {
        if (explicit != null) return explicit
        return generateExampleValue(schema, type, 0, argValueDepth)
    }

    private fun getSelectionSet(
        schema: GraphQLSchema,
        type: GraphQLType,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String> = mutableSetOf(),
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        if (currentDepth > maxDepth) return ""

        val resolved = resolveSchemaType(schema, type)
        return when (val container = resolveFieldsContainer(schema, type)) {
            is GraphQLObjectType, is GraphQLInterfaceType -> handleObjectType(
                schema, container, currentDepth, maxDepth, visitedTypes,
                variablesMap, variableDefinitions, nestedVarCounter,
            )
            else -> when (val unwrapped = Utils.unwrapType(resolved)) {
                is GraphQLUnionType -> handleUnionType(
                    schema, unwrapped, currentDepth, maxDepth, visitedTypes,
                    variablesMap, variableDefinitions, nestedVarCounter,
                )
                else -> ""
            }
        }
    }

    private fun handleObjectType(
        schema: GraphQLSchema,
        type: GraphQLFieldsContainer,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String>,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        if (visitedTypes.contains(type.name)) return ""
        visitedTypes.add(type.name)

        val fields = type.fieldDefinitions
            .filterNot { it.isDeprecated || isSchemaPlaceholderField(it.name) }
            .sortedBy { it.name }
            .mapNotNull { field ->
                buildFieldSelection(
                    schema = schema,
                    field = field,
                    currentDepth = currentDepth,
                    maxDepth = maxDepth,
                    visitedTypes = visitedTypes,
                    variablesMap = variablesMap,
                    variableDefinitions = variableDefinitions,
                    nestedVarCounter = nestedVarCounter,
                )
            }
            .joinToString("\n")

        val finalFields = if (fields.isBlank()) {
            "  ".repeat(currentDepth + 1) + "__typename"
        } else {
            fields
        }

        visitedTypes.remove(type.name)
        return finalFields
    }

    private fun buildFieldSelection(
        schema: GraphQLSchema,
        field: GraphQLFieldDefinition,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String>,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String? {
        if (isSchemaPlaceholderField(field.name)) return null
        val nextDepth = currentDepth + 1
        val fieldType = resolveSchemaType(schema, field.type)
        val unwrappedFieldType = Utils.unwrapType(fieldType)
        val args = processFieldArguments(
            schema = schema,
            field = field,
            currentDepth = nextDepth,
            maxDepth = maxDepth,
            variablesMap = variablesMap,
            variableDefinitions = variableDefinitions,
            nestedVarCounter = nestedVarCounter,
        )
        val padding = "  ".repeat(nextDepth)

        if (isScalarOrEnum(unwrappedFieldType)) {
            return padding + field.name + args
        }

        if (unwrappedFieldType is GraphQLUnionType) {
            return wrapCompositeFieldSelection(
                fieldName = field.name,
                args = args,
                padding = padding,
            ) {
                if (nextDepth > maxDepth) {
                    depthLimitUnionSelection(
                        schema,
                        nextDepth,
                        unwrappedFieldType,
                        maxDepth,
                        variablesMap,
                        variableDefinitions,
                        nestedVarCounter,
                    )
                } else {
                    handleUnionType(
                        schema = schema,
                        type = unwrappedFieldType,
                        currentDepth = nextDepth,
                        maxDepth = maxDepth,
                        visitedTypes = visitedTypes.toMutableSet(),
                        variablesMap = variablesMap,
                        variableDefinitions = variableDefinitions,
                        nestedVarCounter = nestedVarCounter,
                    )
                }
            }
        }

        val container = resolveFieldsContainer(schema, field.type) ?: return null

        return wrapCompositeFieldSelection(
            fieldName = field.name,
            args = args,
            padding = padding,
        ) {
            if (nextDepth > maxDepth) {
                depthLimitSelection(
                    schema,
                    nextDepth,
                    container,
                    maxDepth,
                    variablesMap,
                    variableDefinitions,
                    nestedVarCounter,
                )
            } else {
                val nested = getSelectionSet(
                    schema = schema,
                    type = field.type,
                    currentDepth = nextDepth,
                    maxDepth = maxDepth,
                    visitedTypes = visitedTypes.toMutableSet(),
                    variablesMap = variablesMap,
                    variableDefinitions = variableDefinitions,
                    nestedVarCounter = nestedVarCounter,
                )
                if (nested.isNotBlank()) {
                    nested
                } else {
                    depthLimitSelection(
                        schema,
                        nextDepth,
                        container,
                        maxDepth,
                        variablesMap,
                        variableDefinitions,
                        nestedVarCounter,
                    )
                }
            }
        }
    }

    private fun wrapCompositeFieldSelection(
        fieldName: String,
        args: String,
        padding: String,
        bodyProvider: () -> String,
    ): String {
        val body = bodyProvider()
        return """
            |$padding$fieldName$args {
            |$body
            |$padding}
            """.trimMargin()
    }

    private fun processFieldArguments(
        schema: GraphQLSchema,
        field: GraphQLFieldDefinition,
        currentDepth: Int,
        maxDepth: Int,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        if (field.arguments.isEmpty()) return ""

        val argsList = mutableListOf<String>()
        val argValueDepth = maxDepth + 3

        field.arguments.forEach { arg ->
            val inputContext = InputFieldContext(
                inputTypeName = field.name,
                fieldName = arg.name,
            )
            val exampleValue = generateExampleValue(schema, arg.type, 0, argValueDepth, inputContext)
                ?: requiredArgumentFallback(schema, arg.type, inputContext)
                ?: permissiveArgumentFallback(schema, arg.type, inputContext)
            exampleValue?.let { value ->
                val varName = "${field.name}_${arg.name}_${nestedVarCounter[0]++}"
                val varType = getVariableType(schema, arg.type)

                variableDefinitions.add("$$varName: $varType")
                variablesMap[varName] = value
                argsList.add("${arg.name}: $${varName}")
            }
        }

        return if (argsList.isNotEmpty()) "(${argsList.joinToString(", ")})" else ""
    }

    /**
     * History schemas often omit `!` on arguments the server still requires.
     * Emit a best-effort value so generated requests stay executable.
     */
    private fun permissiveArgumentFallback(
        schema: GraphQLSchema,
        type: GraphQLType,
        inputContext: InputFieldContext,
    ): Any? {
        val resolved = resolveSchemaType(schema, type)
        return when (val unwrapped = Utils.unwrapType(resolved)) {
            is GraphQLEnumType -> preferredEnumValue(unwrapped, inputContext)
            is GraphQLScalarType -> generateLeafExampleValue(schema, resolved, 0, 3, inputContext)
            is GraphQLInputObjectType -> buildInputObjectValue(schema, unwrapped, 0, 3).takeIf { it.isNotEmpty() }
            else -> namedTypeName(resolved)?.let { typeName ->
                (schema.getType(typeName) as? GraphQLEnumType)?.let { preferredEnumValue(it, inputContext) }
            }
        }
    }


    private fun handleUnionType(
        schema: GraphQLSchema,
        type: GraphQLUnionType,
        currentDepth: Int,
        maxDepth: Int,
        visitedTypes: MutableSet<String>,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        val fragmentDepth = currentDepth + 1
        val selections = type.types.mapNotNull { possibleType ->
            val member = resolveFieldsContainer(schema, possibleType) as? GraphQLObjectType ?: return@mapNotNull null
            val nested = getSelectionSet(
                schema = schema,
                type = member,
                currentDepth = fragmentDepth + 1,
                maxDepth = maxDepth,
                visitedTypes = visitedTypes.toMutableSet(),
                variablesMap = variablesMap,
                variableDefinitions = variableDefinitions,
                nestedVarCounter = nestedVarCounter,
            )
            if (nested.isBlank()) {
                return@mapNotNull """
                    |${"  ".repeat(fragmentDepth)}... on ${member.name} {
                    |${scalarFieldsSelection(schema, member, fragmentDepth + 1, maxDepth, variablesMap, variableDefinitions, nestedVarCounter)}
                    |${"  ".repeat(fragmentDepth)}}
                    """.trimMargin()
            }
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

    private fun depthLimitUnionSelection(
        schema: GraphQLSchema,
        depth: Int,
        union: GraphQLUnionType,
        maxDepth: Int,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        val fragmentDepth = depth + 1
        return union.types.mapNotNull { possibleType ->
            val member = resolveFieldsContainer(schema, possibleType) as? GraphQLObjectType ?: return@mapNotNull null
            """
            |${"  ".repeat(fragmentDepth)}... on ${member.name} {
            |${scalarFieldsSelection(schema, member, fragmentDepth + 1, maxDepth, variablesMap, variableDefinitions, nestedVarCounter)}
            |${"  ".repeat(fragmentDepth)}}
            """.trimMargin()
        }.joinToString("\n").ifBlank {
            "  ".repeat(fragmentDepth) + "__typename"
        }
    }

    private fun depthLimitSelection(
        schema: GraphQLSchema,
        depth: Int,
        container: GraphQLFieldsContainer,
        maxDepth: Int,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        return scalarFieldsSelection(
            schema,
            container,
            depth + 1,
            maxDepth,
            variablesMap,
            variableDefinitions,
            nestedVarCounter,
        )
    }

    private fun scalarFieldsSelection(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
        depth: Int,
        maxDepth: Int,
        variablesMap: MutableMap<String, Any?>,
        variableDefinitions: MutableList<String>,
        nestedVarCounter: MutableList<Int>,
    ): String {
        val padding = "  ".repeat(depth)
        val scalars = container.fieldDefinitions
            .filterNot { it.isDeprecated || isSchemaPlaceholderField(it.name) }
            .sortedBy { it.name }
            .mapNotNull { field ->
                if (!isScalarOrEnum(resolveSchemaType(schema, field.type))) return@mapNotNull null
                val args = processFieldArguments(
                    schema = schema,
                    field = field,
                    currentDepth = depth,
                    maxDepth = maxDepth,
                    variablesMap = variablesMap,
                    variableDefinitions = variableDefinitions,
                    nestedVarCounter = nestedVarCounter,
                )
                padding + field.name + args
            }
        if (scalars.isEmpty()) {
            return padding + "__typename"
        }
        return scalars.joinToString("\n")
    }

    private fun buildInputObjectValue(
        schema: GraphQLSchema,
        inputType: GraphQLInputObjectType,
        depth: Int,
        maxDepth: Int,
    ): Map<String, Any?> {
        return inputType.fieldDefinitions
            .filterNot { isSchemaPlaceholderField(it.name) }
            .mapNotNull { field ->
                val ctx = InputFieldContext(inputType.name, field.name)
                val value = generateExampleValue(schema, field.type, depth + 1, maxDepth, ctx)
                    ?: exampleValueForInputField(schema, field.type, ctx)
                value?.let { field.name to it }
            }
            .toMap()
    }

    private fun isScalarOrEnum(type: GraphQLType): Boolean {
        val unwrapped = Utils.unwrapType(type)
        return unwrapped is GraphQLScalarType || unwrapped is GraphQLEnumType
    }

    private fun generateExampleValue(
        schema: GraphQLSchema,
        type: GraphQLType,
        currentDepth: Int = 0,
        maxDepth: Int = 3,
        inputContext: InputFieldContext? = null,
    ): Any? {
        if (currentDepth > maxDepth) {
            return inputContext?.let { correctionEnumValue(it) }
        }

        inputContext?.let { correctionEnumValue(it) }?.let { return it }

        return when (type) {
            is GraphQLNonNull -> generateExampleValue(schema, type.wrappedType, currentDepth, maxDepth, inputContext)
            is GraphQLList -> {
                val element = generateExampleValue(schema, type.wrappedType, currentDepth + 1, maxDepth, inputContext)
                    ?: inputContext?.let { correctionEnumValue(it) }
                if (element != null) listOf(element) else null
            }
            else -> generateLeafExampleValue(schema, type, currentDepth, maxDepth, inputContext)
        }
    }

    private fun generateLeafExampleValue(
        schema: GraphQLSchema,
        type: GraphQLType,
        currentDepth: Int,
        maxDepth: Int,
        inputContext: InputFieldContext?,
    ): Any? {
        val resolved = resolveSchemaType(schema, type)
        return when (val unwrapped = Utils.unwrapType(resolved)) {
            is GraphQLEnumType -> preferredEnumValue(unwrapped, inputContext)
            is GraphQLInputObjectType -> buildInputObjectValue(schema, unwrapped, currentDepth, maxDepth)
                .takeIf { it.isNotEmpty() }
            is GraphQLScalarType -> when (unwrapped.name) {
                "String" -> inputContext?.let { exampleValueForInputField(schema, type, it) } ?: "exampleString"
                "Int" -> 42
                "Float" -> 3.14
                "Boolean" -> true
                "ID" -> "123"
                else -> "exampleString"
            }
            is GraphQLNamedType -> (schema.getType(unwrapped.name) as? GraphQLInputObjectType)
                ?.let { buildInputObjectValue(schema, it, currentDepth, maxDepth).takeIf { map -> map.isNotEmpty() } }
                ?: inputContext?.let { exampleValueForInputField(schema, type, it) }
            else -> inputContext?.let { exampleValueForInputField(schema, type, it) }
        }
    }

    private fun exampleValueForInputField(
        schema: GraphQLSchema,
        type: GraphQLType,
        ctx: InputFieldContext,
    ): Any? {
        correctionEnumValue(ctx)?.let { return it }
        val resolved = resolveSchemaType(schema, type)
        val unwrapped = Utils.unwrapType(resolved)
        if (unwrapped is GraphQLEnumType) {
            return preferredEnumValue(unwrapped, ctx)
        }
        if (unwrapped is GraphQLScalarType && unwrapped.name == "String") {
            return InputEnumTypeMatching.resolveEnumForInputField(schema, ctx.inputTypeName, ctx.fieldName)
                ?.let { preferredEnumValue(it, ctx) }
        }
        val typeName = when (unwrapped) {
            is GraphQLNamedType -> unwrapped.name
            is GraphQLTypeReference -> unwrapped.name
            else -> null
        }
        if (typeName != null) {
            (schema.getType(typeName) as? GraphQLEnumType)?.let { return preferredEnumValue(it, ctx) }
        }
        return null
    }

    private fun correctionEnumValue(ctx: InputFieldContext): String? {
        return scanResults.schemaCorrections.inputEnumFieldOverrides[ctx.inputTypeName]
            ?.get(ctx.fieldName)
            ?.firstOrNull { !isSchemaPlaceholderField(it) }
    }

    private fun resolveSchemaType(schema: GraphQLSchema, type: GraphQLType): GraphQLType {
        val unwrapped = Utils.unwrapType(type)
        val name = when (unwrapped) {
            is GraphQLNamedType -> unwrapped.name
            is GraphQLTypeReference -> unwrapped.name
            else -> return unwrapped
        }
        return schema.getType(name) ?: unwrapped
    }

    private fun resolveFieldsContainer(schema: GraphQLSchema, type: GraphQLType): GraphQLFieldsContainer? {
        return when (val resolved = resolveSchemaType(schema, type)) {
            is GraphQLFieldsContainer -> resolved
            else -> null
        }
    }

    private fun namedTypeName(type: GraphQLType): String? {
        return when (val unwrapped = Utils.unwrapType(type)) {
            is GraphQLNamedType -> unwrapped.name
            is GraphQLTypeReference -> unwrapped.name
            else -> null
        }
    }

    private fun requiredArgumentFallback(
        schema: GraphQLSchema,
        type: GraphQLType,
        inputContext: InputFieldContext,
    ): Any? {
        if (type !is GraphQLNonNull) return null
        val resolved = resolveSchemaType(schema, type)
        return when (val unwrapped = Utils.unwrapType(resolved)) {
            is GraphQLEnumType -> preferredEnumValue(unwrapped, inputContext)
            is GraphQLScalarType -> generateLeafExampleValue(schema, resolved, 0, 3, inputContext)
            is GraphQLInputObjectType -> buildInputObjectValue(schema, unwrapped, 0, 3).takeIf { it.isNotEmpty() }
            else -> namedTypeName(resolved)?.let { typeName ->
                (schema.getType(typeName) as? GraphQLEnumType)?.let { preferredEnumValue(it, inputContext) }
            }
        }
    }

    private fun preferredEnumValue(enumType: GraphQLEnumType, inputContext: InputFieldContext? = null): String {
        inputContext?.let { correctionEnumValue(it) }?.let { return it }
        scanResults.schemaCorrections.enumValueOverrides[enumType.name]
            ?.firstOrNull { !isSchemaPlaceholderField(it) }
            ?.let { return it }
        val values = enumType.values.map { it.name }
        return values.firstOrNull { !isSchemaPlaceholderField(it) }
            ?: values.firstOrNull()
            ?: "PLACEHOLDER"
    }

    private fun getVariableType(schema: GraphQLSchema, type: GraphQLType): String {
        return when (type) {
            is GraphQLNonNull -> "${getVariableType(schema, type.wrappedType)}!"
            is GraphQLList -> "[${getVariableType(schema, type.wrappedType)}]"
            is GraphQLScalarType -> type.name
            is GraphQLEnumType -> type.name
            is GraphQLInputObjectType -> type.name
            is GraphQLNamedType -> type.name
            is GraphQLTypeReference -> type.name
            else -> namedTypeName(resolveSchemaType(schema, type)) ?: "String"
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

    private fun formatVariablesToJson(value: Any?): String {
        if (value == null) return "null"
        return when (value) {
            is String -> "\"${value.replace("\"", "\\\"")}\""
            is Number -> value.toString()
            is Boolean -> value.toString()
            is Map<*, *> -> {
                val entries = value.entries.joinToString(", ") { (k, v) ->
                    "\"$k\": ${formatVariablesToJson(v)}"
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
