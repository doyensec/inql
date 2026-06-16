package inql.graphql.scanners

import graphql.schema.*
import inql.graphql.GQLSchema
import inql.graphql.Utils

class PathEnumerationScanner(
    private val schema: GQLSchema,
    private val maxDepth: Int,
    private val includeQuery: Boolean,
    private val includeMutation: Boolean,
    private val includeSubscription: Boolean,
    private val maxResults: Int = 50_000,
) {
    private val results = mutableListOf<PathResult>()

    fun enumerate(target: PathSearchTarget): List<PathResult> {
        results.clear()

        val roots = buildList {
            if (includeQuery) {
                schema.queries.forEach { (name, def) ->
                    add(Triple(name, def, GQLSchema.OperationType.QUERY))
                }
            }
            if (includeMutation) {
                schema.mutations.forEach { (name, def) ->
                    add(Triple(name, def, GQLSchema.OperationType.MUTATION))
                }
            }
            if (includeSubscription) {
                schema.subscriptions.forEach { (name, def) ->
                    add(Triple(name, def, GQLSchema.OperationType.SUBSCRIPTION))
                }
            }
        }

        for ((rootFieldName, rootFieldDef, operationType) in roots) {
            if (results.size >= maxResults) break
            exploreRootField(operationType, rootFieldName, rootFieldDef, target)
        }

        return results
            .distinctBy { Triple(it.operationType, it.pathFieldNames, it.targetKind) }
            .sortedBy { it.pathFieldNames.size }
    }

    private fun exploreRootField(
        operationType: GQLSchema.OperationType,
        rootFieldName: String,
        rootFieldDef: GraphQLFieldDefinition,
        target: PathSearchTarget,
    ) {
        val path = listOf(rootFieldName)
        val rootContainer = operationRootContainer(operationType) ?: return

        recordMatch(operationType, path, rootContainer, rootFieldDef, target)

        val nextContainer = fieldsContainer(rootFieldDef.type) ?: return

        explore(
            operationType = operationType,
            container = nextContainer,
            path = path,
            visitedTypes = setOf(nextContainer.name),
            depth = 1,
            target = target,
        )
    }

    private fun explore(
        operationType: GQLSchema.OperationType,
        container: GraphQLFieldsContainer,
        path: List<String>,
        visitedTypes: Set<String>,
        depth: Int,
        target: PathSearchTarget,
    ) {
        if (depth > maxDepth || results.size >= maxResults) return

        for (field in container.fieldDefinitions) {
            if (isSchemaPlaceholderField(field.name) || field.isDeprecated) continue

            val newPath = path + field.name
            recordMatch(operationType, newPath, container, field, target)

            val nextContainer = fieldsContainer(field.type) ?: continue
            if (nextContainer.name in visitedTypes) continue

            explore(
                operationType = operationType,
                container = nextContainer,
                path = newPath,
                visitedTypes = visitedTypes + nextContainer.name,
                depth = depth + 1,
                target = target,
            )
        }
    }

    private fun recordMatch(
        operationType: GQLSchema.OperationType,
        path: List<String>,
        container: GraphQLFieldsContainer,
        field: GraphQLFieldDefinition,
        target: PathSearchTarget,
    ) {
        when (target) {
            is PathSearchTarget.TypeTarget -> {
                val unwrapped = Utils.unwrapType(resolveType(field.type))
                if (typeNameMatches(unwrapped, target.typeName)) {
                    results.add(
                        PathResult(
                            operationType = operationType,
                            pathFieldNames = path,
                            targetKind = PathTargetKind.TYPE,
                            targetTypeName = target.typeName,
                        ),
                    )
                }
            }

            is PathSearchTarget.FieldTarget -> {
                if (field.name != target.fieldName) return
                if (target.declaringTypeNames.isNotEmpty() && container.name !in target.declaringTypeNames) return
                results.add(
                    PathResult(
                        operationType = operationType,
                        pathFieldNames = path,
                        targetKind = PathTargetKind.FIELD,
                        targetFieldName = target.fieldName,
                    ),
                )
            }
        }
    }

    private fun operationRootContainer(operationType: GQLSchema.OperationType): GraphQLFieldsContainer? {
        return when (operationType) {
            GQLSchema.OperationType.QUERY -> schema.schema.queryType
            GQLSchema.OperationType.MUTATION -> schema.schema.mutationType
            GQLSchema.OperationType.SUBSCRIPTION -> schema.schema.subscriptionType
        }
    }

    private fun fieldsContainer(type: GraphQLType): GraphQLFieldsContainer? {
        return when (val unwrapped = Utils.unwrapType(resolveType(type))) {
            is GraphQLObjectType -> unwrapped
            is GraphQLInterfaceType -> unwrapped
            else -> null
        }
    }

    private fun resolveType(type: GraphQLType): GraphQLType {
        val unwrapped = Utils.unwrapType(type)
        val name = when (unwrapped) {
            is GraphQLNamedType -> unwrapped.name
            is GraphQLTypeReference -> unwrapped.name
            else -> return unwrapped
        }
        return schema.schema.getType(name) ?: unwrapped
    }

    private fun typeNameMatches(type: GraphQLType, targetTypeName: String): Boolean {
        val name = when (val unwrapped = Utils.unwrapType(type)) {
            is GraphQLNamedType -> unwrapped.name
            is GraphQLTypeReference -> unwrapped.name
            else -> return false
        }
        return name == targetTypeName
    }

    private fun isSchemaPlaceholderField(fieldName: String): Boolean {
        return fieldName == "_inql_placeholder" || fieldName == "PLACEHOLDER"
    }
}
