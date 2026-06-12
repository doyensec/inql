package inql.schema.corrections

import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInterfaceType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType

/**
 * Walks object/interface fields (and relay edges/nodes) for schema-correction path pickers.
 */
object SchemaPathWalker {
    private val relayStructuralSegments = setOf("edges", "nodes", "node", "pageinfo")
    private val placeholderFields = setOf("_inql_placeholder", "PLACEHOLDER")

    data class SegmentOption(
        val label: String,
        val kind: Kind,
    ) {
        enum class Kind {
            FIELD,
            RELAY_EDGES,
            RELAY_NODES,
        }
    }

    fun rootTypeNames(schema: GraphQLSchema): List<String> {
        return buildList {
            schema.queryType?.name?.let { add(it) }
            schema.mutationType?.name?.let { add(it) }
            schema.subscriptionType?.name?.let { add(it) }
            schema.typeMap.values
                .filterIsInstance<GraphQLObjectType>()
                .map { it.name }
                .filter { it !in this@buildList && !it.startsWith("__") }
                .sorted()
                .forEach { add(it) }
        }.distinct()
    }

    fun container(schema: GraphQLSchema, typeName: String): GraphQLFieldsContainer? {
        return schema.getType(typeName) as? GraphQLFieldsContainer
    }

    fun segmentOptions(schema: GraphQLSchema, container: GraphQLFieldsContainer): List<SegmentOption> {
        val options = mutableListOf<SegmentOption>()
        if (container is GraphQLObjectType && container.name.endsWith("Connection")) {
            if (container.getFieldDefinition("edges") != null) {
                options.add(SegmentOption("edges", SegmentOption.Kind.RELAY_EDGES))
            }
            if (container.getFieldDefinition("nodes") != null) {
                options.add(SegmentOption("nodes", SegmentOption.Kind.RELAY_NODES))
            }
        }
        for (field in container.fieldDefinitions.sortedBy { it.name }) {
            if (field.name in placeholderFields || field.name.startsWith("__")) continue
            if (field.name.lowercase() in relayStructuralSegments) continue
            options.add(SegmentOption(field.name, SegmentOption.Kind.FIELD))
        }
        return options
    }

    fun follow(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
        segment: String,
    ): GraphQLFieldsContainer? {
        val normalized = segment.lowercase()
        return when (normalized) {
            "edges" -> connectionEdgeNodeContainer(schema, container)
            "nodes" -> connectionNodesContainer(schema, container)
            "node" -> connectionEdgeNodeContainer(schema, container)
            else -> {
                val field = container.getFieldDefinition(segment) ?: return null
                fieldsContainer(schema, field.type)
            }
        }
    }

    fun walk(
        schema: GraphQLSchema,
        rootTypeName: String,
        segments: List<String>,
    ): GraphQLFieldsContainer? {
        var current = container(schema, rootTypeName) ?: return null
        for (segment in segments) {
            if (segment.isBlank()) continue
            current = follow(schema, current, segment) ?: return null
        }
        return current
    }

    fun inputTypeNames(schema: GraphQLSchema): List<String> {
        return schema.typeMap.values
            .filterIsInstance<graphql.schema.GraphQLInputObjectType>()
            .map { it.name }
            .filter { !it.startsWith("__") }
            .sorted()
    }

    fun inputFieldNames(schema: GraphQLSchema, inputTypeName: String): List<String> {
        val input = schema.getType(inputTypeName) as? graphql.schema.GraphQLInputObjectType ?: return emptyList()
        return input.fieldDefinitions
            .map { it.name }
            .filter { it !in placeholderFields }
            .sorted()
    }

    fun inputFieldBaseType(schema: GraphQLSchema, inputTypeName: String, fieldName: String): String? {
        val input = schema.getType(inputTypeName) as? graphql.schema.GraphQLInputObjectType ?: return null
        val field = input.getFieldDefinition(fieldName) ?: return null
        return graphql.schema.GraphQLTypeUtil.simplePrint(field.type)
            .removeSuffix("!")
            .removePrefix("[")
            .removeSuffix("]")
            .trim()
    }

    fun isNestedInputType(schema: GraphQLSchema, baseTypeName: String): Boolean {
        return schema.getType(baseTypeName) is graphql.schema.GraphQLInputObjectType
    }

    fun resolveInputFieldPath(
        schema: GraphQLSchema,
        rootInputType: String,
        fieldPath: List<String>,
    ): Pair<String, String>? {
        if (fieldPath.isEmpty()) return null
        var currentType = rootInputType
        for (index in fieldPath.indices) {
            val segment = fieldPath[index]
            if (index == fieldPath.lastIndex) {
                return currentType to segment
            }
            val nextType = inputFieldBaseType(schema, currentType, segment) ?: return null
            if (!isNestedInputType(schema, nextType)) return null
            currentType = nextType
        }
        return null
    }

    fun formatPath(segments: List<String>): String {
        return segments.filter { it.isNotBlank() }.joinToString(".")
    }

    fun findInputFieldDisplayPath(
        schema: GraphQLSchema,
        leafInputType: String,
        fieldName: String,
    ): String {
        for (root in inputTypeNames(schema)) {
            if (root == leafInputType && fieldName in inputFieldNames(schema, root)) {
                return "$root.$fieldName"
            }
            val path = findInputFieldPathFromRoot(schema, root, leafInputType, fieldName, emptyList())
            if (path != null) {
                return formatPath(listOf(root) + path)
            }
        }
        return "$leafInputType.$fieldName"
    }

    private fun findInputFieldPathFromRoot(
        schema: GraphQLSchema,
        currentType: String,
        leafInputType: String,
        fieldName: String,
        pathSoFar: List<String>,
    ): List<String>? {
        if (currentType == leafInputType) {
            if (inputFieldNames(schema, currentType).contains(fieldName)) {
                return pathSoFar + fieldName
            }
            return null
        }
        for (field in inputFieldNames(schema, currentType)) {
            val nextType = inputFieldBaseType(schema, currentType, field) ?: continue
            if (!isNestedInputType(schema, nextType)) continue
            val found = findInputFieldPathFromRoot(
                schema,
                nextType,
                leafInputType,
                fieldName,
                pathSoFar + field,
            )
            if (found != null) return found
        }
        return null
    }

    private fun fieldsContainer(schema: GraphQLSchema, type: GraphQLType): GraphQLFieldsContainer? {
        val named = unwrap(type)
        when (named) {
            is GraphQLObjectType, is GraphQLInterfaceType -> return named
            is GraphQLUnionType -> return named.types.firstOrNull() as? GraphQLFieldsContainer
        }
        val typeName = (named as? graphql.schema.GraphQLNamedType)?.name ?: return null
        return schema.getType(typeName) as? GraphQLFieldsContainer
    }

    private fun connectionNodesContainer(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
    ): GraphQLFieldsContainer? {
        val nodesField = container.getFieldDefinition("nodes") ?: return null
        return fieldsContainer(schema, nodesField.type)
    }

    private fun connectionEdgeNodeContainer(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
    ): GraphQLFieldsContainer? {
        val edgesField = container.getFieldDefinition("edges") ?: return null
        val edgeType = unwrapList(edgesField.type) ?: return null
        val edgeContainer = fieldsContainer(schema, edgeType) ?: return null
        val nodeField = edgeContainer.getFieldDefinition("node") ?: return null
        return fieldsContainer(schema, nodeField.type)
    }

    private fun unwrap(type: GraphQLType): GraphQLType {
        return when (type) {
            is graphql.schema.GraphQLNonNull -> unwrap(type.wrappedType)
            is graphql.schema.GraphQLList -> unwrap(type.wrappedType)
            else -> type
        }
    }

    private fun unwrapList(type: GraphQLType): GraphQLType? {
        return when (type) {
            is graphql.schema.GraphQLNonNull -> unwrapList(type.wrappedType)
            is graphql.schema.GraphQLList -> unwrap(type.wrappedType)
            else -> unwrap(type)
        }
    }
}
