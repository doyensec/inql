package inql.history

import graphql.language.*
import graphql.parser.Parser
import graphql.schema.GraphQLSchema
import inql.Logger
import inql.graphql.Utils

/**
 * Converts a GraphQL operation string into a partial executable schema.
 */
internal object QueryAstToSchema {
    private val parser = Parser()

    data class FieldNode(
        val name: String,
        val arguments: Map<String, String>,
        val children: List<FieldNode> = emptyList(),
        val scalarReturnType: String? = null,
        val inlineFragments: Map<String, List<FieldNode>> = emptyMap(),
        val hasSubselection: Boolean = false,
    )

    private data class SelectionExtract(
        val fields: List<FieldNode> = emptyList(),
        val inlineFragments: Map<String, List<FieldNode>> = emptyMap(),
    )

    private data class SchemaBuildContext(
        val enumValues: MutableMap<String, LinkedHashSet<String>>,
        val inlineInputFields: MutableMap<String, MutableMap<String, String>>,
    )

    fun buildSchema(
        query: String,
        operationType: String,
        rejectedFieldNames: Set<String> = emptySet(),
        responseBody: String? = null,
        variables: Map<String, Any?>? = null,
        errorHints: GraphQLErrorTypeHints.Hints = GraphQLErrorTypeHints.Hints(),
    ): GraphQLSchema? {
        if (!Utils.isGraphQLDocument(query)) return null
        return try {
            val document = parser.parseDocument(query)
            val fragmentMap = buildFragmentMap(document)
            val operation = document.definitions
                .filterIsInstance<OperationDefinition>()
                .firstOrNull() ?: return null

            val effectiveOperationType = resolveOperationType(operation, operationType)
            val rootTypeName = when (effectiveOperationType) {
                "mutation" -> "Mutation"
                "subscription" -> "Subscription"
                else -> "Query"
            }

            val variableTypes = GraphQLTypeInference.buildVariableTypeMap(operation)
            val responseData = ResponseDataParser.extractData(responseBody)
            val buildContext = SchemaBuildContext(
                enumValues = linkedMapOf(),
                inlineInputFields = linkedMapOf(),
            )
            val rootExtract = extractSelectionSet(
                selectionSet = operation.selectionSet,
                fragmentMap = fragmentMap,
                rejectedFieldNames = rejectedFieldNames,
                variableTypes = variableTypes,
                responseNode = responseData,
                operationType = effectiveOperationType,
                errorHints = errorHints,
                buildContext = buildContext,
            )
            if (rootExtract.fields.isEmpty() && rootExtract.inlineFragments.isEmpty()) return null

            val registry = SdlTypeRegistry()
            registry.addFields(rootTypeName, rootExtract.fields)
            for ((typeName, fragmentFields) in rootExtract.inlineFragments) {
                registry.addFields(typeName, fragmentFields)
            }
            for ((inputTypeName, fields) in buildContext.inlineInputFields) {
                registry.registerInputFields(inputTypeName, fields)
            }
            registry.applyArgumentTypeHints(errorHints.argumentHints)
            if (!variables.isNullOrEmpty()) {
                JsonValueTypeInference.applyVariableValues(registry, variables, variableTypes)
            }
            for ((enumName, values) in buildContext.enumValues) {
                registry.registerEnumValues(enumName, values)
            }
            registry.toSchema()
        } catch (e: Exception) {
            Logger.debug("Failed to build schema from query AST: ${e.message}")
            null
        }
    }

    private fun resolveOperationType(operation: OperationDefinition, fallback: String): String {
        return when (operation.operation) {
            OperationDefinition.Operation.MUTATION -> "mutation"
            OperationDefinition.Operation.SUBSCRIPTION -> "subscription"
            OperationDefinition.Operation.QUERY -> "query"
            null -> fallback.lowercase()
        }
    }

    private fun buildFragmentMap(document: Document): Map<String, FragmentDefinition> {
        return document.definitions
            .filterIsInstance<FragmentDefinition>()
            .associateBy { it.name }
    }

    private fun extractSelectionSet(
        selectionSet: SelectionSet?,
        fragmentMap: Map<String, FragmentDefinition>,
        rejectedFieldNames: Set<String>,
        variableTypes: Map<String, String>,
        responseNode: Any?,
        operationType: String,
        errorHints: GraphQLErrorTypeHints.Hints,
        buildContext: SchemaBuildContext,
    ): SelectionExtract {
        if (selectionSet == null) return SelectionExtract()

        val fields = mutableListOf<FieldNode>()
        val inlineFragments = linkedMapOf<String, MutableList<FieldNode>>()

        for (selection in selectionSet.selections) {
            when (selection) {
                is Field -> {
                    val fieldName = selection.name
                    if (fieldName in rejectedFieldNames || fieldName.startsWith("__")) continue

                    val argumentHints = errorHints.argumentHints
                        .filter { it.fieldName == fieldName }
                        .associate { it.argumentName to it.expectedType }

                    val args = selection.arguments.associate { arg ->
                        val inferenceContext = ValueInferenceContext(
                            operationType = operationType,
                            parentFieldName = fieldName,
                            argumentName = arg.name,
                            argumentTypeHints = argumentHints,
                            enumValues = buildContext.enumValues,
                        )
                        val argType = inferArgumentType(arg, variableTypes, inferenceContext, buildContext)
                        arg.name to argType
                    }

                    val fieldResponse = ResponseDataParser.normalizeResponseNode(
                        ResponseDataParser.responseValueForField(responseNode, fieldName, selection.alias),
                    )
                    val childExtract = extractSelectionSet(
                        selection.selectionSet,
                        fragmentMap,
                        rejectedFieldNames,
                        variableTypes,
                        fieldResponse,
                        operationType,
                        errorHints,
                        buildContext,
                    )
                    val hasSubselection = selection.selectionSet?.selections?.isNotEmpty() == true
                    val scalarReturnType = if (
                        !hasSubselection &&
                        childExtract.fields.isEmpty() &&
                        childExtract.inlineFragments.isEmpty()
                    ) {
                        GraphQLTypeInference.inferReturnTypeFromResponse(fieldResponse, fieldName)
                    } else {
                        null
                    }
                    fields.add(
                        FieldNode(
                            name = fieldName,
                            arguments = args,
                            children = childExtract.fields,
                            scalarReturnType = scalarReturnType,
                            inlineFragments = childExtract.inlineFragments,
                            hasSubselection = hasSubselection,
                        ),
                    )
                }

                is InlineFragment -> {
                    val typeName = fragmentTypeName(selection.typeCondition) ?: continue
                    val fragExtract = extractSelectionSet(
                        selection.selectionSet,
                        fragmentMap,
                        rejectedFieldNames,
                        variableTypes,
                        responseNode,
                        operationType,
                        errorHints,
                        buildContext,
                    )
                    mergeFragmentExtract(inlineFragments, typeName, fragExtract)
                }

                is FragmentSpread -> {
                    val fragment = fragmentMap[selection.name] ?: continue
                    val typeName = fragmentTypeName(fragment.typeCondition)
                    val fragExtract = extractSelectionSet(
                        fragment.selectionSet,
                        fragmentMap,
                        rejectedFieldNames,
                        variableTypes,
                        responseNode,
                        operationType,
                        errorHints,
                        buildContext,
                    )
                    if (typeName != null) {
                        mergeFragmentExtract(inlineFragments, typeName, fragExtract)
                    } else {
                        fields.addAll(
                            fragExtract.fields.map { field ->
                                field.copy(
                                    inlineFragments = field.inlineFragments + fragExtract.inlineFragments,
                                )
                            },
                        )
                        for ((nestedType, nestedFields) in fragExtract.inlineFragments) {
                            mergeFragmentExtract(
                                inlineFragments,
                                nestedType,
                                SelectionExtract(nestedFields),
                            )
                        }
                    }
                }
            }
        }

        return SelectionExtract(
            fields = fields,
            inlineFragments = inlineFragments.mapValues { it.value.toList() },
        )
    }

    private fun inferArgumentType(
        arg: Argument,
        variableTypes: Map<String, String>,
        context: ValueInferenceContext,
        buildContext: SchemaBuildContext,
    ): String {
        var argType = GraphQLTypeInference.inferValueType(arg.value, variableTypes, context)
        if (arg.value is ObjectValue) {
            argType = GraphQLTypeInference.ensureNonNullSdlType(argType)
        }
        if (arg.value is ObjectValue) {
            val inputTypeName = GraphQLTypeInference.baseTypeName(argType)
            val fields = GraphQLTypeInference.extractObjectFields(
                arg.value as ObjectValue,
                variableTypes,
                inputTypeName,
                context,
            )
            val bucket = buildContext.inlineInputFields.getOrPut(inputTypeName) { linkedMapOf() }
            for ((fieldName, fieldType) in fields) {
                bucket[fieldName] = GraphQLTypeInference.mergeSdlTypes(bucket[fieldName], fieldType)
            }
        }
        return argType
    }

    private fun mergeFragmentExtract(
        inlineFragments: MutableMap<String, MutableList<FieldNode>>,
        typeName: String,
        extract: SelectionExtract,
    ) {
        val bucket = inlineFragments.getOrPut(typeName) { mutableListOf() }
        bucket.addAll(extract.fields)
        for ((nestedType, nestedFields) in extract.inlineFragments) {
            mergeFragmentExtract(inlineFragments, nestedType, SelectionExtract(nestedFields))
        }
    }

    private fun fragmentTypeName(typeCondition: Type<*>?): String? {
        return (typeCondition as? TypeName)?.name
    }
}
