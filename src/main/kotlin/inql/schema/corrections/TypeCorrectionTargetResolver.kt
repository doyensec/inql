package inql.schema.corrections

import graphql.language.Field
import graphql.language.FragmentDefinition
import graphql.language.FragmentSpread
import graphql.language.InlineFragment
import graphql.language.OperationDefinition
import graphql.language.SelectionSet
import graphql.language.TypeName
import graphql.parser.Parser
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInterfaceType
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType
import inql.graphql.Utils

/**
 * Finds argument locations that reference a synthetic/wrong input type so corrections can be
 * scoped to specific fields instead of renaming the type globally.
 */
object TypeCorrectionTargetResolver {
    fun argumentSitesInQuery(
        schema: GraphQLSchema,
        query: String,
        operationType: String,
        wrongType: String,
    ): List<SchemaArgumentPathResolver.ResolvedArgument> {
        val document = runCatching { Parser().parseDocument(Utils.normalizeGraphQLDocument(query)) }.getOrNull()
            ?: return emptyList()
        val fragmentMap = document.definitions
            .filterIsInstance<FragmentDefinition>()
            .associateBy { it.name }
        val operation = document.definitions
            .filterIsInstance<OperationDefinition>()
            .firstOrNull { it.operation != OperationDefinition.Operation.SUBSCRIPTION }
            ?: return emptyList()

        val root = when (operation.operation) {
            OperationDefinition.Operation.MUTATION -> schema.mutationType
            OperationDefinition.Operation.SUBSCRIPTION -> schema.subscriptionType
            OperationDefinition.Operation.QUERY, null -> schema.queryType
        } ?: return emptyList()

        val sites = linkedSetOf<SchemaArgumentPathResolver.ResolvedArgument>()
        walkSelectionSet(
            selectionSet = operation.selectionSet,
            parentType = root,
            schema = schema,
            wrongType = wrongType,
            sites = sites,
            fragmentMap = fragmentMap,
        )
        return sites.toList()
    }

    fun argumentSitesInSchema(
        schema: GraphQLSchema,
        wrongType: String,
    ): List<SchemaArgumentPathResolver.ResolvedArgument> {
        val sites = linkedSetOf<SchemaArgumentPathResolver.ResolvedArgument>()
        for (type in schema.allTypesAsList) {
            val container = type as? GraphQLFieldsContainer ?: continue
            for (field in container.fieldDefinitions) {
                for (argument in field.arguments) {
                    if (GraphQLErrorPathParser.normalizeTypeName(typeName(argument.type)) == wrongType) {
                        sites.add(
                            SchemaArgumentPathResolver.ResolvedArgument(
                                parentType = container.name,
                                fieldName = field.name,
                                argumentName = argument.name,
                            ),
                        )
                    }
                }
            }
        }
        return sites.toList()
    }

    private fun walkSelectionSet(
        selectionSet: SelectionSet?,
        parentType: GraphQLFieldsContainer,
        schema: GraphQLSchema,
        wrongType: String,
        sites: MutableSet<SchemaArgumentPathResolver.ResolvedArgument>,
        fragmentMap: Map<String, FragmentDefinition>,
    ) {
        if (selectionSet == null) return
        for (selection in selectionSet.selections) {
            when (selection) {
                is Field -> {
                    if (selection.name.startsWith("__")) continue
                    val field = parentType.getFieldDefinition(selection.name) ?: continue
                    for (argument in field.arguments) {
                        if (GraphQLErrorPathParser.normalizeTypeName(typeName(argument.type)) == wrongType) {
                            sites.add(
                                SchemaArgumentPathResolver.ResolvedArgument(
                                    parentType = parentType.name,
                                    fieldName = field.name,
                                    argumentName = argument.name,
                                ),
                            )
                        }
                    }
                    val childContainer = resolveFieldsContainer(schema, field.type) ?: continue
                    walkSelectionSet(
                        selectionSet = selection.selectionSet,
                        parentType = childContainer,
                        schema = schema,
                        wrongType = wrongType,
                        sites = sites,
                        fragmentMap = fragmentMap,
                    )
                }
                is InlineFragment -> {
                    val container = resolveTypeCondition(schema, selection.typeCondition, parentType)
                    walkSelectionSet(
                        selectionSet = selection.selectionSet,
                        parentType = container,
                        schema = schema,
                        wrongType = wrongType,
                        sites = sites,
                        fragmentMap = fragmentMap,
                    )
                }
                is FragmentSpread -> {
                    val fragment = fragmentMap[selection.name] ?: continue
                    val container = resolveTypeCondition(schema, fragment.typeCondition, parentType)
                    walkSelectionSet(
                        selectionSet = fragment.selectionSet,
                        parentType = container,
                        schema = schema,
                        wrongType = wrongType,
                        sites = sites,
                        fragmentMap = fragmentMap,
                    )
                }
            }
        }
    }

    private fun resolveTypeCondition(
        schema: GraphQLSchema,
        typeCondition: graphql.language.Type<*>?,
        fallback: GraphQLFieldsContainer,
    ): GraphQLFieldsContainer {
        val name = (typeCondition as? TypeName)?.name ?: return fallback
        return resolveFieldsContainer(schema, schema.getType(name) as? GraphQLType) ?: fallback
    }

    private fun resolveFieldsContainer(schema: GraphQLSchema, type: GraphQLType?): GraphQLFieldsContainer? {
        val resolved = unwrap(type) ?: return null
        return when (resolved) {
            is GraphQLObjectType -> resolved
            is GraphQLInterfaceType -> resolved
            is GraphQLUnionType -> resolved.types.firstOrNull() as? GraphQLFieldsContainer
            is GraphQLNamedType -> (schema.getType(resolved.name) as? GraphQLFieldsContainer)
            else -> null
        }
    }

    private fun unwrap(type: GraphQLType?): GraphQLType? {
        var current = type ?: return null
        while (current is graphql.schema.GraphQLNonNull || current is graphql.schema.GraphQLList) {
            current = when (current) {
                is graphql.schema.GraphQLNonNull -> current.wrappedType
                is graphql.schema.GraphQLList -> current.wrappedType
                else -> break
            }
        }
        return current
    }

    private fun typeName(type: GraphQLType): String? {
        return when (val unwrapped = unwrap(type)) {
            is GraphQLNamedType -> unwrapped.name
            else -> null
        }
    }
}
