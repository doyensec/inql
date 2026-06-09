package inql.history

import graphql.language.*
import graphql.parser.Parser
import graphql.schema.GraphQLSchema
import inql.Logger
import inql.graphql.Utils

/**
 * Converts a GraphQL operation string into a partial executable schema.
 */
object QueryAstToSchema {
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

    fun buildSchema(
        query: String,
        operationType: String,
        rejectedFieldNames: Set<String> = emptySet(),
        responseBody: String? = null,
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
            val rootExtract = extractSelectionSet(
                operation.selectionSet,
                fragmentMap,
                rejectedFieldNames,
                variableTypes,
                responseData,
            )
            if (rootExtract.fields.isEmpty() && rootExtract.inlineFragments.isEmpty()) return null

            val registry = SdlTypeRegistry()
            registry.addFields(rootTypeName, rootExtract.fields)
            for ((typeName, fragmentFields) in rootExtract.inlineFragments) {
                registry.addFields(typeName, fragmentFields)
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
    ): SelectionExtract {
        if (selectionSet == null) return SelectionExtract()

        val fields = mutableListOf<FieldNode>()
        val inlineFragments = linkedMapOf<String, MutableList<FieldNode>>()

        for (selection in selectionSet.selections) {
            when (selection) {
                is Field -> {
                    val fieldName = selection.name
                    if (fieldName in rejectedFieldNames || fieldName.startsWith("__")) continue
                    val args = selection.arguments.associate { arg ->
                        arg.name to GraphQLTypeInference.inferValueType(arg.value, variableTypes)
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
                    )
                    val hasSubselection = selection.selectionSet?.selections?.isNotEmpty() == true
                    val scalarReturnType = if (
                        !hasSubselection &&
                        childExtract.fields.isEmpty() &&
                        childExtract.inlineFragments.isEmpty()
                    ) {
                        GraphQLTypeInference.inferScalarFromJson(fieldResponse)
                            ?: GraphQLTypeInference.inferScalarFromFieldName(fieldName)
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
