package inql.schema.corrections

import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType
import inql.history.ConnectionNodeTypeNaming
import org.json.JSONArray

object SchemaArgumentPathResolver {
    data class ResolvedArgument(
        val parentType: String,
        val fieldName: String,
        val argumentName: String,
    )

    fun parseArgumentLocation(path: JSONArray?): Pair<String, String>? {
        val segments = toSegments(path) ?: return null
        if (segments.size < 2) return null
        val argumentName = segments.last()
        val fieldName = segments[segments.size - 2]
        return fieldName to argumentName
    }

    /**
     * Resolves argument location using only the server error path (relay segment inference).
     * Use for schema corrections — avoids mis-attribution when the history schema wires
     * connection edges incorrectly.
     */
    fun resolveArgumentFromErrorPath(
        schema: GraphQLSchema,
        path: JSONArray?,
        fieldName: String? = null,
        argumentName: String? = null,
    ): ResolvedArgument? {
        val segments = toSegments(path) ?: return null
        val resolvedFieldName = fieldName?.takeIf { it.isNotBlank() }
            ?: segments.getOrNull(segments.size - 2)
        val resolvedArgumentName = argumentName?.takeIf { it.isNotBlank() }
            ?: segments.lastOrNull()
        if (resolvedFieldName.isNullOrBlank() || resolvedArgumentName.isNullOrBlank()) return null

        val parentType = resolveParentTypeBySchemaWalk(schema, segments, resolvedFieldName)
            ?: resolveConnectionNodeTypeAtPath(schema, segments, resolvedFieldName)
            ?: run {
                val inferred = inferParentTypeNameFromPath(segments, resolvedFieldName) ?: return null
                canonicalParentTypeForPath(schema, segments, resolvedFieldName, inferred)
            }
        return ResolvedArgument(
            parentType = parentType,
            fieldName = resolvedFieldName,
            argumentName = resolvedArgumentName,
        )
    }

    fun resolveArgument(
        schema: GraphQLSchema,
        path: JSONArray?,
        fieldName: String? = null,
        argumentName: String? = null,
    ): ResolvedArgument? {
        val segments = toSegments(path)
        val resolvedFieldName = fieldName?.takeIf { it.isNotBlank() }
            ?: segments?.getOrNull(segments.size - 2)
        val resolvedArgumentName = argumentName?.takeIf { it.isNotBlank() }
            ?: segments?.lastOrNull()
        if (resolvedFieldName.isNullOrBlank() || resolvedArgumentName.isNullOrBlank()) return null

        resolveParentTypeName(schema, segments, resolvedFieldName)?.let { parentType ->
            return ResolvedArgument(
                parentType = parentType,
                fieldName = resolvedFieldName,
                argumentName = resolvedArgumentName,
            )
        }

        return null
    }

    fun inferredParentTypeFromErrorPath(path: JSONArray?, fieldName: String): String? {
        val segments = toSegments(path) ?: return null
        return inferParentTypeNameFromPath(segments, fieldName)
    }

    fun inferParentTypeNameFromPath(segments: List<String>, fieldName: String): String? {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex <= 0) return null

        val prefix = segments.take(fieldIndex).filterNot { isListIndex(it) }

        val beforeField = prefix.lastOrNull() ?: return null
        if (beforeField.lowercase() !in relaySegments) {
            return segmentToTypeName(beforeField)
        }

        for (index in prefix.indices.reversed()) {
            when (prefix[index].lowercase()) {
                "nodes", "node" -> {
                    if (index > 0 && isDirectConnectionNodeChild(segments, fieldName, index)) {
                        val connectionField = prefix[index - 1]
                        val parentPrefix = prefix.take(index - 1)
                        val parentType = inferParentTypeNameFromPath(
                            parentPrefix + listOf("_"),
                            "_",
                        ) ?: if (parentPrefix.isEmpty()) {
                            defaultRootTypeName(segments)
                        } else {
                            return null
                        }
                        return ConnectionNodeTypeNaming.synthetic(parentType, connectionField)
                    }
                }
            }
        }

        return null
    }

    private fun resolveParentTypeBySchemaWalk(
        schema: GraphQLSchema,
        segments: List<String>,
        fieldName: String,
    ): String? {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex <= 0) return null
        val root = schema.queryType ?: schema.mutationType ?: schema.subscriptionType ?: return null
        return walkPath(schema, root, segments.take(fieldIndex))?.let { walked ->
            walked.takeIf { it.getFieldDefinition(fieldName) != null }?.name
        }
    }

    private fun isDirectConnectionNodeChild(
        segments: List<String>,
        fieldName: String,
        relayIndexInFilteredPrefix: Int,
    ): Boolean {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        val prefix = segments.take(fieldIndex).filterNot { isListIndex(it) }
        if (relayIndexInFilteredPrefix != prefix.size - 1) return false
        val relayIndexInFull = segments.take(fieldIndex).indexOfLast {
            it.equals(prefix[relayIndexInFilteredPrefix], ignoreCase = true)
        }
        if (relayIndexInFull < 0) return false
        return segments.subList(relayIndexInFull + 1, fieldIndex).all { isListIndex(it) }
    }

    private fun resolveParentTypeName(
        schema: GraphQLSchema,
        segments: List<String>?,
        fieldName: String,
    ): String? {
        if (segments.isNullOrEmpty()) {
            return findParentByField(schema, fieldName)?.name
        }

        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex > 0) {
            guessTypeFromPathSegment(schema, segments[fieldIndex - 1])?.name?.let { return it }
        }

        val inferred = inferParentTypeNameFromPath(segments, fieldName)
        return inferred?.let { canonicalParentTypeForPath(schema, segments, fieldName, it) }
            ?: findParentByField(schema, fieldName)?.name
    }

    private fun canonicalParentTypeForPath(
        schema: GraphQLSchema,
        segments: List<String>,
        fieldName: String,
        inferred: String,
    ): String {
        resolveConnectionNodeTypeAtPath(schema, segments, fieldName)?.let { return it }

        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex > 0) {
            val root = schema.queryType ?: schema.mutationType ?: schema.subscriptionType
            if (root != null) {
                walkPath(schema, root, segments.take(fieldIndex))?.let { walked ->
                    if (walked.getFieldDefinition(fieldName) != null) {
                        return walked.name
                    }
                }
            }
        }

        schemaTypeWithField(schema, inferred, fieldName)?.let { return it }
        return inferred
    }

    private fun schemaTypeWithField(
        schema: GraphQLSchema,
        typeName: String,
        fieldName: String,
    ): String? {
        return (schema.getType(typeName) as? GraphQLObjectType)
            ?.takeIf { it.getFieldDefinition(fieldName) != null }
            ?.name
    }

    private fun resolveConnectionNodeTypeAtPath(
        schema: GraphQLSchema,
        segments: List<String>,
        fieldName: String,
    ): String? {
        if (!isFieldDirectConnectionNodeChild(segments, fieldName)) return null
        val connectionField = connectionFieldBeforeField(segments, fieldName) ?: return null
        val fieldIndex = segments.indexOfLast { it == fieldName }
        val prefix = segments.take(fieldIndex)
        val connectionIndex = prefix.indexOfLast { it == connectionField }
        if (connectionIndex < 0) return null
        val prefixBeforeConnection = prefix.take(connectionIndex)

        val root = schema.queryType ?: schema.mutationType ?: schema.subscriptionType ?: return null
        val parentContainer = if (prefixBeforeConnection.isEmpty()) {
            root
        } else {
            walkPath(schema, root, prefixBeforeConnection) ?: return null
        }

        val nodeType = connectionNodesType(schema, parentContainer, connectionField) ?: return null
        if (parentContainer is GraphQLObjectType && nodeType.name == parentContainer.name) {
            // Reject mis-wired relay fields (e.g. Organization.teams -> Organization).
            return null
        }
        return nodeType.takeIf { it.getFieldDefinition(fieldName) != null }?.name
    }

    private fun isFieldDirectConnectionNodeChild(segments: List<String>, fieldName: String): Boolean {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex <= 0) return false
        val prefix = segments.take(fieldIndex).filterNot { isListIndex(it) }
        val relayIndex = prefix.indexOfLast { it.lowercase() in relaySegments }
        if (relayIndex < 0) return false
        return isDirectConnectionNodeChild(segments, fieldName, relayIndex)
    }

    private fun connectionFieldBeforeField(segments: List<String>, fieldName: String): String? {
        val fieldIndex = segments.indexOfLast { it == fieldName }
        if (fieldIndex <= 0) return null
        val prefix = segments.take(fieldIndex)
        for (index in prefix.indices.reversed()) {
            when (prefix[index].lowercase()) {
                "nodes", "node" -> if (index > 0) return prefix[index - 1]
            }
        }
        return null
    }

    private fun segmentToTypeName(segment: String): String {
        return segment.split('_')
            .filter { it.isNotBlank() }
            .joinToString("") { part -> part.replaceFirstChar { char -> char.uppercase() } }
    }

    private fun findParentByField(schema: GraphQLSchema, fieldName: String): GraphQLObjectType? {
        val matches = schema.allTypesAsList
            .filterIsInstance<GraphQLObjectType>()
            .filter { type -> type.getFieldDefinition(fieldName) != null }
        return matches.singleOrNull()
    }

    private fun guessTypeFromPathSegment(schema: GraphQLSchema, segment: String): GraphQLObjectType? {
        if (segment.lowercase() in relaySegments) return null
        for (candidate in segmentTypeNameCandidates(segment)) {
            (schema.getType(candidate) as? GraphQLObjectType)?.let { return it }
        }
        return null
    }

    private fun segmentTypeNameCandidates(segment: String): List<String> {
        val pascal = segmentToTypeName(segment)
        return listOf(pascal, segment.replaceFirstChar { char -> char.uppercase() }).distinct()
    }

    private val relaySegments = setOf("edges", "node", "nodes", "pageinfo")

    private fun walkPath(
        schema: GraphQLSchema,
        start: GraphQLFieldsContainer,
        segments: List<String>,
    ): GraphQLObjectType? {
        var container: GraphQLFieldsContainer = start
        var lastFieldName: String? = null
        var index = 0

        while (index < segments.size) {
            val segment = segments[index]
            if (isListIndex(segment)) {
                index++
                continue
            }
            when (segment.lowercase()) {
                "edges" -> {
                    val nodeType = resolveRelayNodeType(schema, container, lastFieldName, viaEdges = true) ?: return null
                    index++
                    if (index < segments.size && segments[index].equals("node", ignoreCase = true)) {
                        index++
                    }
                    skipListIndices(segments, index).also { index = it }
                    container = nodeType
                    lastFieldName = null
                }
                "nodes" -> {
                    val nodeType = resolveRelayNodeType(schema, container, lastFieldName, viaEdges = false) ?: return null
                    index++
                    skipListIndices(segments, index).also { index = it }
                    container = nodeType
                    lastFieldName = null
                }
                "pageInfo", "pageinfo" -> return null
                else -> {
                    val field = container.getFieldDefinition(segment) ?: return null
                    lastFieldName = segment
                    container = fieldOutputContainer(schema, field.type) ?: return null
                    index++
                }
            }
        }

        return container as? GraphQLObjectType
    }

    private fun isListIndex(segment: String): Boolean = segment.toIntOrNull() != null

    private fun skipListIndices(segments: List<String>, startIndex: Int): Int {
        var index = startIndex
        while (index < segments.size && isListIndex(segments[index])) {
            index++
        }
        return index
    }

    private fun defaultRootTypeName(segments: List<String>): String {
        return segments.firstOrNull { GraphQLErrorPathParser.operationRootType(it) != null }
            ?.let { GraphQLErrorPathParser.operationRootType(it) }
            ?: "Query"
    }

    private fun resolveRelayNodeType(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
        lastFieldName: String?,
        viaEdges: Boolean,
    ): GraphQLObjectType? {
        if (lastFieldName != null) {
            val fromField = if (viaEdges) {
                connectionNodeType(schema, container, lastFieldName)
            } else {
                connectionNodesType(schema, container, lastFieldName)
            }
            if (fromField != null) return fromField
        }
        return if (viaEdges) {
            directConnectionEdgeNodeType(schema, container)
        } else {
            directConnectionNodesType(schema, container)
        }
    }

    private fun directConnectionNodesType(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
    ): GraphQLObjectType? {
        val nodesField = container.getFieldDefinition("nodes") ?: return null
        return fieldOutputContainer(schema, nodesField.type) as? GraphQLObjectType
    }

    private fun directConnectionEdgeNodeType(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
    ): GraphQLObjectType? {
        val edgesField = container.getFieldDefinition("edges") ?: return null
        val edgeType = unwrapListElement(edgesField.type) as? GraphQLObjectType ?: return null
        val nodeField = edgeType.getFieldDefinition("node") ?: return null
        return fieldOutputContainer(schema, nodeField.type) as? GraphQLObjectType
    }

    private fun connectionNodeType(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
        fieldName: String,
    ): GraphQLObjectType? {
        val connectionField = container.getFieldDefinition(fieldName) ?: return null
        val connectionType = unwrapNamed(connectionField.type) as? GraphQLObjectType ?: return null
        val edgesField = connectionType.getFieldDefinition("edges") ?: return null
        val edgeType = unwrapListElement(edgesField.type) as? GraphQLObjectType ?: return null
        val nodeField = edgeType.getFieldDefinition("node") ?: return null
        return fieldOutputContainer(schema, nodeField.type) as? GraphQLObjectType
    }

    private fun connectionNodesType(
        schema: GraphQLSchema,
        container: GraphQLFieldsContainer,
        fieldName: String,
    ): GraphQLObjectType? {
        val connectionField = container.getFieldDefinition(fieldName) ?: return null
        val named = unwrapNamed(connectionField.type) ?: return null
        val connectionType = named as? GraphQLObjectType
        if (connectionType != null) {
            val nodesField = connectionType.getFieldDefinition("nodes") ?: return null
            fieldOutputContainer(schema, nodesField.type)?.let { containerType ->
                return containerType as? GraphQLObjectType
            }
        }
        return fieldOutputContainer(schema, named) as? GraphQLObjectType
    }

    private fun fieldOutputContainer(schema: GraphQLSchema?, type: GraphQLType): GraphQLFieldsContainer? {
        val named = unwrapNamed(type)
        if (named is GraphQLFieldsContainer) return named
        if (named is GraphQLUnionType && named.types.isNotEmpty()) {
            return named.types.firstOrNull() as? GraphQLFieldsContainer
        }
        val typeName = (named as? GraphQLNamedType)?.name ?: return null
        return schema?.getType(typeName) as? GraphQLFieldsContainer
    }

    private fun unwrapNamed(type: GraphQLType): GraphQLType? {
        return when (type) {
            is graphql.schema.GraphQLNonNull -> unwrapNamed(type.wrappedType)
            is graphql.schema.GraphQLList -> unwrapNamed(type.wrappedType)
            else -> type
        }
    }

    private fun unwrapListElement(type: GraphQLType): GraphQLType? {
        return when (type) {
            is graphql.schema.GraphQLNonNull -> unwrapListElement(type.wrappedType)
            is graphql.schema.GraphQLList -> unwrapNamed(type.wrappedType)
            else -> unwrapNamed(type)
        }
    }

    private fun toSegments(path: JSONArray?): List<String>? {
        if (path == null || path.length() == 0) return null
        val segments = (0 until path.length()).mapNotNull { index ->
            when (val value = path.opt(index)) {
                is String -> value
                else -> value?.toString()
            }
        }
        val trimmed = segments.dropWhile { segment ->
            GraphQLErrorPathParser.operationRootType(segment) != null
        }
        return trimmed.ifEmpty { null }
    }
}
