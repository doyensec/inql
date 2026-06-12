package inql.history

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType
import graphql.schema.idl.SchemaGenerator
import graphql.schema.idl.SchemaParser
import graphql.schema.idl.errors.SchemaProblem
import inql.graphql.SchemaInspectionRuntimeWiring
import inql.Logger
import inql.schema.corrections.InputEnumTypeMatching
import inql.schema.corrections.SchemaCorrections

/**
 * Builds partial GraphQL schemas via SDL text to avoid graphql-java type reference casting issues.
 */
internal class SdlTypeRegistry {
    companion object {
        internal var lastGeneratedSdl: String? = null
    }
    data class SdlField(
        var returnType: String,
        val arguments: MutableMap<String, String> = mutableMapOf(),
    )

    private val types = linkedMapOf<String, MutableMap<String, SdlField>>()
    private val unionTypes = linkedMapOf<String, LinkedHashSet<String>>()
    private val inputTypes = linkedMapOf<String, MutableMap<String, SdlField>>()
    private val enumTypes = linkedSetOf<String>()
    private val enumValues = linkedMapOf<String, LinkedHashSet<String>>()
    private val scalarTypes = linkedSetOf<String>()
    private val rootTypeNames = setOf("Query", "Mutation", "Subscription")
    private val builtInScalars = setOf("String", "Int", "Float", "Boolean", "ID")
    /** Connection fields that are metadata/scalars, not entity lists. */
    private val connectionMetadataFieldNames = setOf(
        "pageinfo", "totalcount", "total_count", "aggregate", "edge",
    )
    private var typeAliases: Map<String, String> = emptyMap()
    private var blockedTypeNames: Set<String> = emptySet()
    private val alternateReturnTypes = linkedMapOf<Pair<String, String>, LinkedHashSet<String>>()
    var lastSchemaBuildError: String? = null
        private set

    private data class RelayConnectionShape(
        val nodeFields: List<QueryAstToSchema.FieldNode>,
        val nodeInlineFragments: Map<String, List<QueryAstToSchema.FieldNode>> = emptyMap(),
        val nodeTypeName: String?,
        val pageInfoField: QueryAstToSchema.FieldNode?,
        val viaEdges: Boolean,
        val listFieldName: String = "nodes",
    )

    fun setTypeAliases(aliases: Map<String, String>) {
        typeAliases = aliases
    }

    fun setBlockedTypeNames(names: Set<String>) {
        blockedTypeNames = names
    }

    fun resolveTypeAlias(typeName: String): String {
        return typeAliases[typeName] ?: typeName
    }

    fun addFields(
        parentType: String,
        fieldNodes: List<QueryAstToSchema.FieldNode>,
        evidencedParent: Boolean = false,
    ) {
        ensureOutputType(parentType)
        if (parentType.endsWith("Connection")) {
            addFieldsToConnection(parentType, fieldNodes)
            return
        }
        for (field in fieldNodes) {
            when {
                field.inlineFragments.isNotEmpty() -> {
                    if (field.inlineFragments.size == 1) {
                        val (memberType, memberFields) = field.inlineFragments.entries.first()
                        addFields(memberType, memberFields, evidencedParent = true)
                        mergeField(parentType, field.name, memberType, field.arguments)
                    } else {
                        val unionName = unionTypeNameForField(field.name, parentType)
                        for ((memberType, memberFields) in field.inlineFragments) {
                            addFields(memberType, memberFields, evidencedParent = true)
                            addUnionMember(unionName, memberType)
                        }
                        mergeField(parentType, field.name, unionName, field.arguments)
                    }
                }

                field.children.isNotEmpty() -> {
                    val relayShape = detectRelayConnectionShape(field.children)
                    if (relayShape != null) {
                        registerRelayConnection(parentType, field, relayShape)
                        continue
                    }
                    val childType = resolveCompositeChildType(parentType, field, evidencedParent) ?: continue
                    addFields(childType, field.children, evidencedParent = true)
                    for ((memberType, memberFields) in field.inlineFragments) {
                        addFields(memberType, memberFields, evidencedParent = true)
                    }
                    mergeField(parentType, field.name, childType, field.arguments)
                }

                field.hasSubselection -> {
                    val childType = resolveCompositeChildType(parentType, field, evidencedParent) ?: continue
                    if (field.children.isNotEmpty() || field.inlineFragments.isNotEmpty()) {
                        addFields(childType, field.children, evidencedParent = true)
                        for ((memberType, memberFields) in field.inlineFragments) {
                            addFields(memberType, memberFields, evidencedParent = true)
                        }
                    } else {
                        ensureOutputType(childType)
                    }
                    mergeField(parentType, field.name, childType, field.arguments)
                }

                else -> {
                    val returnType = field.scalarReturnType
                        ?: queryEvidencedScalarType(field, evidencedParent)
                        ?: continue
                    mergeField(parentType, field.name, returnType, field.arguments)
                }
            }
        }
    }

    private fun resolveChildTypeName(field: QueryAstToSchema.FieldNode): String? {
        return field.objectTypeName
            ?.takeIf { isUserDefinedOutputType(it) }
            ?.let { resolveTypeAlias(it) }
    }

    private fun resolveCompositeChildType(
        parentType: String,
        field: QueryAstToSchema.FieldNode,
        evidencedParent: Boolean,
    ): String? {
        val fromTypename = resolveChildTypeName(field)
        val fromQuery = queryEvidencedChildTypeName(parentType, field, evidencedParent)
        when {
            fromTypename != null && fromQuery != null && fromTypename != fromQuery -> {
                recordAlternateReturnType(parentType, field.name, fromTypename)
                recordAlternateReturnType(parentType, field.name, fromQuery)
            }
            fromTypename != null -> recordAlternateReturnType(parentType, field.name, fromTypename)
            fromQuery != null -> recordAlternateReturnType(parentType, field.name, fromQuery)
        }
        return fromTypename ?: fromQuery
    }

    fun registerInputFields(typeName: String, fields: Map<String, String>) {
        if (fields.isEmpty()) return
        if (GraphQLTypeInference.isKnownCustomScalar(typeName)) {
            ensureArgumentTypeStub(typeName)
            return
        }
        val bucket = inputTypes.getOrPut(typeName) { mutableMapOf() }
        for ((fieldName, fieldType) in fields) {
            val existing = bucket[fieldName]
            if (existing == null) {
                bucket[fieldName] = SdlField(fieldType)
            } else {
                existing.returnType = GraphQLTypeInference.mergeSdlTypes(existing.returnType, fieldType)
            }
        }
        bucket.remove("_inql_placeholder")
        registerArgumentReferencedTypes(fields.values)
    }

    fun registerEnumValues(typeName: String, values: Collection<String>) {
        if (!isUserDefinedType(typeName)) return
        val filtered = values.filter { it != "PLACEHOLDER" && it != "_inql_placeholder" }
        if (filtered.isEmpty()) {
            ensureEnumStub(typeName)
            return
        }
        enumTypes.add(typeName)
        inputTypes.remove(typeName)
        val bucket = enumValues.getOrPut(typeName) { linkedSetOf() }
        bucket.addAll(filtered)
        bucket.remove("PLACEHOLDER")
        bucket.remove("_inql_placeholder")
    }

    fun ensureEnumStub(typeName: String) {
        if (!isUserDefinedType(typeName)) return
        if (typeName in inputTypes && inputTypes[typeName]!!.keys.any { !isSchemaPlaceholderField(it) }) return
        enumTypes.add(typeName)
        inputTypes.remove(typeName)
        val bucket = enumValues.getOrPut(typeName) { linkedSetOf() }
        if (bucket.isEmpty()) {
            bucket.add("PLACEHOLDER")
        }
    }

    fun registerVariableDeclarationTypes(variableTypes: Map<String, String>) {
        for ((_, declaredType) in variableTypes) {
            val base = GraphQLTypeInference.baseTypeName(declaredType)
            if (GraphQLTypeInference.isBuiltInScalar(base)) continue
            ensureArgumentTypeStub(base)
        }
    }

    private fun isSchemaPlaceholderField(fieldName: String): Boolean {
        return fieldName == "_inql_placeholder" || fieldName == "PLACEHOLDER"
    }

    fun replaceEnumValues(typeName: String, values: Collection<String>) {
        if (!isUserDefinedType(typeName)) return
        val filtered = values.filter { it != "PLACEHOLDER" && it != "_inql_placeholder" }
        if (filtered.isEmpty()) {
            enumTypes.remove(typeName)
            enumValues.remove(typeName)
            return
        }
        enumTypes.add(typeName)
        enumValues[typeName] = LinkedHashSet(filtered)
    }

    fun importEnumType(type: GraphQLEnumType) {
        if (!isUserDefinedType(type.name)) return
        val values = type.values.map { it.name }
        replaceEnumValues(type.name, values)
    }

    fun applyCorrections(corrections: SchemaCorrections) {
        for ((source, target) in corrections.typeMerges) {
            mergeTypeInto(source, target)
        }
        for ((oldName, newName) in corrections.typeRenames) {
            renameType(oldName, newName)
        }
        for (typeName in corrections.removedTypes) {
            removeType(typeName)
        }
        for ((typeName, fieldNames) in corrections.removedFields) {
            types[typeName]?.keys?.removeAll(fieldNames)
            inputTypes[typeName]?.keys?.removeAll(fieldNames)
        }
        if (corrections.removeAllPlaceholders) {
            removePlaceholderFields()
        }
        for ((typeName, fields) in corrections.fieldTypeOverrides) {
            applyFieldTypeOverrides(typeName, fields)
        }
        consolidateConnectionNodeTypeDuplicates()
        for ((parentType, fieldMap) in corrections.argumentTypeOverrides) {
            applyArgumentTypeOverrides(parentType, fieldMap)
        }
        applyInputEnumFieldOverrides(corrections.inputEnumFieldOverrides)
        applyEnumValueOverrides(corrections.enumValueOverrides)
        ensureReferencedTypeStubs()
    }

    fun applyInferredTypeRenames(renames: List<Pair<String, String>>) {
        for ((oldName, newName) in renames) {
            if (oldName == newName) continue
            renameType(oldName, newName)
        }
    }

    fun applyArgumentTypeHints(hints: List<GraphQLErrorTypeHints.ArgumentTypeHint>) {
        for (hint in hints) {
            val fields = types[hint.parentType]
            val existingReturn = fields?.get(hint.fieldName)?.returnType ?: "String"
            mergeField(
                parentType = hint.parentType,
                fieldName = hint.fieldName,
                returnType = existingReturn,
                arguments = mapOf(hint.argumentName to hint.expectedType),
            )
            registerArgumentReferencedTypes(listOf(hint.expectedType))
        }
    }

    fun addUnionMember(unionName: String, memberType: String) {
        if (unionName == memberType) return
        reserveUnionName(unionName)
        unionTypes.getOrPut(unionName) { linkedSetOf() }.add(memberType)
        ensureOutputType(memberType)
    }

    fun importUnionType(type: GraphQLUnionType) {
        if (!isUserDefinedType(type.name)) return
        reserveUnionName(type.name)
        val members = unionTypes.getOrPut(type.name) { linkedSetOf() }
        for (member in type.types) {
            val memberName = (member as? GraphQLNamedType)?.name ?: continue
            members.add(memberName)
        }
    }

    fun importObjectType(type: GraphQLObjectType) {
        if (!isUserDefinedType(type.name)) return
        ensureOutputType(type.name)
        for (field in type.fieldDefinitions) {
            if (field.name == "_inql_placeholder") continue
            val returnType = graphQLTypeToSdl(field.type)
            val args = field.arguments.associate { it.name to graphQLTypeToSdl(it.type) }
            mergeField(type.name, field.name, returnType, args)
        }
    }

    fun importInputObjectType(type: GraphQLInputObjectType) {
        if (!isUserDefinedType(type.name)) return
        if (type.name in types) return
        val fields = inputTypes.getOrPut(type.name) { mutableMapOf() }
        for (field in type.fieldDefinitions) {
            if (field.name == "_inql_placeholder") continue
            val fieldType = graphQLTypeToSdl(field.type)
            fields[field.name] = SdlField(fieldType)
            registerArgumentReferencedTypes(listOf(fieldType))
        }
        if (fields.isEmpty()) {
            fields["_inql_placeholder"] = SdlField("String")
        }
    }

    fun ensureQueryRoot() {
        if ("Query" !in types) {
            ensureOutputType("Query")
            types["Query"]!!["_inql_placeholder"] = SdlField("String")
        }
    }

    /** Cheap stats for detecting whether a merge changed the registry. */
    data class Snapshot(
        val outputTypes: Int,
        val outputFields: Int,
        val inputTypes: Int,
        val enumTypes: Int,
        val unionTypes: Int,
    )

    fun snapshot(): Snapshot {
        return Snapshot(
            outputTypes = types.size,
            outputFields = countOutputFields(),
            inputTypes = inputTypes.size,
            enumTypes = enumTypes.size,
            unionTypes = unionTypes.size,
        )
    }

    fun countOutputFields(): Int {
        return types.values.sumOf { fields ->
            fields.keys.count { !isSchemaPlaceholderField(it) }
        }
    }

    fun toSchema(): GraphQLSchema? {
        lastSchemaBuildError = null
        ensureQueryRoot()
        ensureReferencedTypeStubs()
        consolidateConnectionNodeTypeDuplicates()
        reconcileAlternateReturnTypes()
        ensureOutputTypesForAllFieldReferences()
        val sdl = toSdl()
        Companion.lastGeneratedSdl = sdl
        return try {
            val registry = SchemaParser().parse(sdl)
            SchemaGenerator().makeExecutableSchema(
                registry,
                SchemaInspectionRuntimeWiring.build(registry),
            )
        } catch (e: SchemaProblem) {
            lastSchemaBuildError = e.errors.joinToString("; ") { it.message ?: it.toString() }
            Logger.debug("Failed to parse generated SDL schema: ${e.message}\nGenerated SDL:\n$sdl")
            null
        } catch (e: Exception) {
            lastSchemaBuildError = e.message ?: e.toString()
            Logger.debug("Failed to build schema from SDL: ${e.message}")
            null
        }
    }

    private fun addFieldsToConnection(
        connectionType: String,
        fieldNodes: List<QueryAstToSchema.FieldNode>,
    ) {
        for (field in fieldNodes) {
            processConnectionField(connectionType, field)
        }
    }

    private fun processConnectionField(
        connectionType: String,
        field: QueryAstToSchema.FieldNode,
    ) {
        when {
            field.name == "edges" -> {
                field.children.find { it.name == "node" }?.let { node ->
                    val nodeShape = relayNodeShape(node) ?: return@let
                    wireRelayEdges(connectionType, nodeShape)
                }
            }
            isConnectionListField(field) -> {
                wireRelayListField(connectionType, field)
            }
            field.name.equals("pageInfo", ignoreCase = true) -> {
                val pageInfoName = "PageInfo"
                ensureOutputType(pageInfoName)
                if (field.children.isNotEmpty()) {
                    addFields(pageInfoName, field.children, evidencedParent = true)
                }
                mergeField(connectionType, "pageInfo", "$pageInfoName!", emptyMap())
            }
            field.name.equals("total_count", ignoreCase = true) ||
                field.name.equals("totalcount", ignoreCase = true) -> {
                val returnType = field.scalarReturnType ?: "Int"
                mergeField(connectionType, field.name, returnType, field.arguments)
            }
            isConnectionMetadataField(field.name) -> {
                val returnType = field.scalarReturnType ?: "String"
                mergeField(connectionType, field.name, returnType, field.arguments)
            }
            field.hasSubselection -> {
                val childType = field.objectTypeName?.takeIf { isUserDefinedOutputType(it) } ?: return
                if (field.children.isNotEmpty()) {
                    addFields(childType, field.children)
                } else {
                    ensureOutputType(childType)
                }
                mergeField(connectionType, field.name, childType, field.arguments)
            }
            else -> {
                val returnType = field.scalarReturnType
                    ?: queryEvidencedScalarType(field, evidencedParent = true)
                    ?: return
                mergeField(connectionType, field.name, returnType, field.arguments)
            }
        }
    }

    private fun isConnectionMetadataField(fieldName: String): Boolean {
        return fieldName.lowercase() in connectionMetadataFieldNames
    }

    private fun hasConnectionListContent(field: QueryAstToSchema.FieldNode): Boolean {
        return field.children.isNotEmpty() || field.inlineFragments.isNotEmpty()
    }

    /** Any sub-selected connection child that is not relay edges or metadata. */
    private fun isConnectionListField(field: QueryAstToSchema.FieldNode): Boolean {
        if (field.name.startsWith("__")) return false
        if (field.name == "edges") return false
        if (isConnectionMetadataField(field.name)) return false
        return hasConnectionListContent(field)
    }

    private fun findDirectConnectionListField(
        children: List<QueryAstToSchema.FieldNode>,
    ): QueryAstToSchema.FieldNode? {
        children.find { it.name == "nodes" && hasConnectionListContent(it) }?.let { return it }
        return children.firstOrNull { isConnectionListField(it) }
    }

    private fun detectRelayConnectionShape(
        children: List<QueryAstToSchema.FieldNode>,
    ): RelayConnectionShape? {
        children.find { it.name == "edges" }?.children?.find { it.name == "node" }?.let { node ->
            if (node.children.isEmpty() && node.inlineFragments.isEmpty()) return@let null
            val nodeShape = relayNodeShape(node) ?: return@let null
            return RelayConnectionShape(
                nodeFields = nodeShape.fields,
                nodeInlineFragments = nodeShape.inlineFragments,
                nodeTypeName = nodeShape.typeName,
                pageInfoField = children.find { it.name == "pageInfo" },
                viaEdges = true,
            )
        }
        findDirectConnectionListField(children)?.let { listField ->
            val nodeShape = relayNodeShape(listField)
            return RelayConnectionShape(
                nodeFields = nodeShape?.fields ?: listField.children,
                nodeInlineFragments = nodeShape?.inlineFragments ?: listField.inlineFragments,
                nodeTypeName = nodeShape?.typeName,
                pageInfoField = children.find { it.name.equals("pageInfo", ignoreCase = true) },
                viaEdges = false,
                listFieldName = listField.name,
            )
        }
        return null
    }

    private data class RelayNodeShape(
        val typeName: String?,
        val fields: List<QueryAstToSchema.FieldNode>,
        val inlineFragments: Map<String, List<QueryAstToSchema.FieldNode>>,
    )

    private fun relayNodeShape(node: QueryAstToSchema.FieldNode): RelayNodeShape? {
        if (node.children.isEmpty() && node.inlineFragments.isEmpty()) return null

        node.objectTypeName?.takeIf { isUserDefinedOutputType(it) }?.let { typeName ->
            val resolved = resolveTypeAlias(typeName)
            if (node.inlineFragments.size <= 1) {
                val fragmentFields = when {
                    node.inlineFragments.isEmpty() -> emptyList()
                    else -> node.inlineFragments[resolved] ?: node.inlineFragments.values.first()
                }
                return RelayNodeShape(
                    typeName = resolved,
                    fields = node.children + fragmentFields,
                    inlineFragments = emptyMap(),
                )
            }
            return RelayNodeShape(
                typeName = unionTypeNameForField(node.name, "ConnectionNode"),
                fields = node.children,
                inlineFragments = node.inlineFragments,
            )
        }

        if (node.inlineFragments.size == 1) {
            val (typeName, fields) = node.inlineFragments.entries.first()
            if (!isUserDefinedOutputType(typeName)) return null
            return RelayNodeShape(
                typeName = resolveTypeAlias(typeName),
                fields = fields,
                inlineFragments = emptyMap(),
            )
        }

        if (node.inlineFragments.isNotEmpty()) {
            return RelayNodeShape(
                typeName = node.inlineFragments.keys.first(),
                fields = node.children,
                inlineFragments = node.inlineFragments,
            )
        }

        return RelayNodeShape(
            typeName = null,
            fields = node.children,
            inlineFragments = emptyMap(),
        )
    }

    private fun registerRelayConnection(
        parentType: String,
        field: QueryAstToSchema.FieldNode,
        shape: RelayConnectionShape,
    ) {
        val nodeTypeName = shape.nodeTypeName?.takeIf { isUserDefinedOutputType(it) }
            ?: syntheticConnectionNodeTypeName(parentType, field.name)
        val nodeShape = RelayNodeShape(
            typeName = nodeTypeName,
            fields = shape.nodeFields,
            inlineFragments = shape.nodeInlineFragments,
        )
        val connectionName = if (shape.nodeInlineFragments.size > 1) {
            "${parentType}${field.name.toPascalCase()}Connection"
        } else {
            "${nodeTypeName.removeSuffix("Connection")}Connection"
        }

        ensureOutputType(connectionName)
        val listField = field.children.find { it.name == shape.listFieldName }
        val resolvedNodeType = resolvedRelayNodeType(connectionName, nodeShape, listField) ?: return
        consolidateConnectionNodeAlias(parentType, field.name, resolvedNodeType)
        if (nodeShape.inlineFragments.isEmpty()) {
            addFields(resolvedNodeType, nodeShape.fields, evidencedParent = true)
        }

        if (shape.viaEdges) {
            val edgeName = "${resolvedNodeType}Edge"
            ensureOutputType(edgeName)
            mergeField(edgeName, "node", resolvedNodeType, emptyMap())
            mergeField(connectionName, "edges", "[$edgeName!]!", emptyMap())
        } else {
            mergeField(connectionName, shape.listFieldName, "[$resolvedNodeType!]!", emptyMap())
        }

        shape.pageInfoField?.let { pageInfo ->
            val pageInfoName = "PageInfo"
            ensureOutputType(pageInfoName)
            if (pageInfo.children.isNotEmpty()) {
                addFields(pageInfoName, pageInfo.children, evidencedParent = true)
            }
            mergeField(connectionName, "pageInfo", "$pageInfoName!", emptyMap())
        }

        mergeField(parentType, field.name, connectionName, field.arguments)
        registerRelayConnectionExtraFields(connectionName, field.children)
    }

    private fun registerRelayConnectionExtraFields(
        connectionType: String,
        children: List<QueryAstToSchema.FieldNode>,
    ) {
        for (child in children) {
            if (child.name.startsWith("__")) continue
            if (child.name == "edges" || isConnectionListField(child)) continue
            if (child.name.equals("pageInfo", ignoreCase = true)) continue
            val returnType = child.scalarReturnType
                ?: queryEvidencedScalarType(child, evidencedParent = true)
                ?: continue
            mergeField(connectionType, child.name, returnType, child.arguments)
        }
    }

    private fun queryEvidencedScalarType(
        field: QueryAstToSchema.FieldNode,
        evidencedParent: Boolean,
    ): String? {
        if (!evidencedParent || field.hasSubselection) return null
        return "String"
    }

    private fun queryEvidencedChildTypeName(
        parentType: String,
        field: QueryAstToSchema.FieldNode,
        evidencedParent: Boolean,
    ): String? {
        if (!evidencedParent || !field.hasSubselection) return null
        field.outputTypeName?.let { return resolveTypeAlias(it) }
        if (field.inlineFragments.size == 1) {
            return field.inlineFragments.keys.first().let { resolveTypeAlias(it) }
        }
        return childTypeName(parentType, field.name)
    }

    private fun childTypeName(parentType: String, fieldName: String): String {
        return ConnectionNodeTypeNaming.child(parentType, fieldName)
    }

    private fun syntheticConnectionNodeTypeName(parentType: String, connectionFieldName: String): String {
        return ConnectionNodeTypeNaming.synthetic(parentType, connectionFieldName)
    }

    private fun consolidateConnectionNodeAlias(
        parentType: String,
        connectionFieldName: String,
        wiredNodeType: String,
    ) {
        val synthetic = syntheticConnectionNodeTypeName(parentType, connectionFieldName)
        if (synthetic != wiredNodeType && types.containsKey(synthetic)) {
            mergeTypeInto(synthetic, wiredNodeType)
        }
    }

    private fun consolidateConnectionNodeTypeDuplicates() {
        for ((parentType, fields) in types.toMap()) {
            for ((fieldName, field) in fields) {
                val connectionType = GraphQLTypeInference.baseTypeName(field.returnType)
                if (!connectionType.endsWith("Connection")) continue
                val wiredNodeType = connectionWiredNodeType(connectionType) ?: continue
                consolidateConnectionNodeAlias(parentType, fieldName, wiredNodeType)
            }
        }
    }

    private fun connectionWiredNodeType(connectionType: String): String? {
        return wiredNodeTypeFromConnectionFields(types[connectionType].orEmpty())
    }

    private fun wireRelayListField(
        connectionType: String,
        listField: QueryAstToSchema.FieldNode,
    ) {
        if (!hasConnectionListContent(listField)) return
        val nodeShape = relayNodeShape(listField) ?: return
        val nodeType = resolvedRelayNodeType(connectionType, nodeShape, listField) ?: return
        mergeField(connectionType, listField.name, "[$nodeType!]!", listField.arguments)
        addFields(nodeType, nodeShape.fields, evidencedParent = true)
        for ((memberType, memberFields) in nodeShape.inlineFragments) {
            addFields(memberType, memberFields, evidencedParent = true)
        }
    }

    private fun wireRelayEdges(connectionType: String, nodeShape: RelayNodeShape) {
        val nodeType = resolvedRelayNodeType(connectionType, nodeShape) ?: return
        val edgeName = "${nodeType}Edge"
        ensureOutputType(edgeName)
        mergeField(edgeName, "node", nodeType, emptyMap())
        mergeField(connectionType, "edges", "[$edgeName!]!", emptyMap())
        if (nodeShape.inlineFragments.isEmpty()) {
            addFields(nodeType, nodeShape.fields, evidencedParent = true)
        }
    }

    private fun resolvedRelayNodeType(
        connectionType: String,
        nodeShape: RelayNodeShape,
        listField: QueryAstToSchema.FieldNode? = null,
    ): String? {
        if (nodeShape.inlineFragments.size > 1) {
            val unionName = unionTypeNameForField("node", connectionType)
            reserveUnionName(unionName)
            for ((memberType, memberFields) in nodeShape.inlineFragments) {
                addFields(memberType, memberFields, evidencedParent = true)
                addUnionMember(unionName, memberType)
            }
            return unionName
        }
        nodeShape.typeName?.takeIf { isUserDefinedOutputType(it) }?.let { typeName ->
            val resolved = resolveTypeAlias(typeName)
            ensureOutputType(resolved)
            return resolved
        }
        listField?.let { field ->
            if (field.name == "elements") {
                naptimeNodeTypeFromElementsField(connectionType, field)?.let { nodeType ->
                    ensureOutputType(nodeType)
                    return nodeType
                }
            }
        }
        inferredNodeTypeFromConnection(connectionType)?.let { nodeType ->
            ensureOutputType(nodeType)
            return nodeType
        }
        return null
    }

    private fun inferredNodeTypeFromConnection(connectionType: String): String? {
        val stripped = connectionType.removeSuffix("Connection")
        if (stripped.isNotEmpty() && isUserDefinedOutputType(stripped)) {
            return stripped
        }
        return null
    }

    private fun wiredNodeTypeFromListReturnType(returnType: String): String? {
        if (!returnType.trimStart().startsWith("[")) return null
        val nodeType = GraphQLTypeInference.baseTypeName(returnType)
        return nodeType.takeIf { isUserDefinedOutputType(it) }
    }

    private fun wiredNodeTypeFromConnectionFields(
        fields: Map<String, SdlField>,
    ): String? {
        for ((fieldName, field) in fields) {
            if (fieldName == "edges") continue
            wiredNodeTypeFromListReturnType(field.returnType)?.let { return it }
        }
        val edgesType = fields["edges"]?.returnType ?: return null
        val edgeTypeName = GraphQLTypeInference.baseTypeName(edgesType)
        val edgeFields = types[edgeTypeName] ?: return null
        val nodeReturn = edgeFields["node"]?.returnType ?: return null
        return GraphQLTypeInference.baseTypeName(nodeReturn).takeIf { isUserDefinedOutputType(it) }
    }

    private fun naptimeNodeTypeFromElementsField(
        connectionType: String,
        elementsField: QueryAstToSchema.FieldNode,
    ): String? {
        elementsField.objectTypeName
            ?.takeIf { isUserDefinedOutputType(it) }
            ?.let { return resolveTypeAlias(it) }
        if (elementsField.inlineFragments.size == 1) {
            return elementsField.inlineFragments.keys.first().let { resolveTypeAlias(it) }
        }
        val stripped = connectionType.removeSuffix("Connection")
        if (stripped.isNotEmpty() && isUserDefinedOutputType(stripped)) {
            return stripped
        }
        return null
    }

    private fun String.toPascalCase(): String {
        if (isBlank()) return this
        return replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    }

    private fun mergeField(
        parentType: String,
        fieldName: String,
        returnType: String,
        arguments: Map<String, String>,
    ) {
        if (parentType in blockedTypeNames) return
        val returnBase = GraphQLTypeInference.baseTypeName(returnType)
        if (returnBase in blockedTypeNames) return
        ensureOutputType(parentType)
        val fields = types[parentType]!!
        val existing = fields[fieldName]
        if (existing == null) {
            fields[fieldName] = SdlField(returnType, arguments.toMutableMap())
        } else {
            arguments.forEach { (name, type) ->
                existing.arguments[name] = GraphQLTypeInference.mergeArgumentSdlTypes(
                    existing.arguments[name],
                    type,
                    parentType,
                    fieldName,
                    name,
                )
            }
            val previousReturn = existing.returnType
            existing.returnType = GraphQLTypeInference.mergeSdlTypes(previousReturn, returnType)
            recordAlternateReturnType(parentType, fieldName, previousReturn)
            recordAlternateReturnType(parentType, fieldName, returnType)
            recordAlternateReturnType(parentType, fieldName, existing.returnType)
        }
        registerArgumentReferencedTypes(arguments.values)
        registerReturnReferencedTypes(listOf(returnType))
    }

    private fun recordAlternateReturnType(parentType: String, fieldName: String, sdlType: String) {
        val base = GraphQLTypeInference.baseTypeName(sdlType)
        if (!isUserDefinedOutputType(base)) return
        alternateReturnTypes.getOrPut(parentType to fieldName) { linkedSetOf() }.add(base)
    }

    private fun evidencedFieldCount(typeName: String): Int {
        return types[typeName]?.keys?.count { !isSchemaPlaceholderField(it) } ?: 0
    }

    private fun reconcileAlternateReturnTypes() {
        for ((parentType, fields) in types.toMap()) {
            for ((fieldName, field) in fields) {
                val currentBase = GraphQLTypeInference.baseTypeName(field.returnType)
                if (!isUserDefinedOutputType(currentBase)) continue

                val candidates = linkedSetOf<String>()
                alternateReturnTypes[parentType to fieldName]?.let { candidates.addAll(it) }
                candidates.add(childTypeName(parentType, fieldName))

                val best = candidates
                    .filter { isUserDefinedOutputType(it) }
                    .map { it to evidencedFieldCount(it) }
                    .sortedWith(compareByDescending<Pair<String, Int>> { it.second }.thenBy { it.first })
                    .firstOrNull()
                    ?: continue
                if (best.second == 0) continue
                if (evidencedFieldCount(currentBase) >= best.second) continue

                field.returnType = rewriteBaseType(field.returnType, currentBase, best.first)
                ensureOutputType(best.first)
            }
        }
    }

    fun ensureArgumentTypeStub(typeName: String) {
        if (!isUserDefinedType(typeName)) return
        if (GraphQLTypeInference.isBuiltInScalar(typeName)) return
        if (GraphQLTypeInference.isKnownCustomScalar(typeName)) {
            inputTypes.remove(typeName)
            enumTypes.remove(typeName)
            enumValues.remove(typeName)
            types.remove(typeName)
            scalarTypes.add(typeName)
            return
        }
        if (typeName in inputTypes || typeName in enumTypes) return
        if (typeName in scalarTypes) return

        when (GraphQLTypeInference.argumentStubKind(typeName, enumValues)) {
            ReferencedTypeKind.ENUM -> ensureEnumStub(typeName)
            ReferencedTypeKind.INPUT -> ensureInputStub(typeName)
            ReferencedTypeKind.SCALAR -> {
                inputTypes.remove(typeName)
                enumTypes.remove(typeName)
                enumValues.remove(typeName)
                types.remove(typeName)
                scalarTypes.add(typeName)
            }
        }
    }

    private fun ensureArgumentTypeStubFromSdl(sdlType: String) {
        for (typeName in GraphQLTypeInference.extractReferencedBaseTypes(sdlType)) {
            ensureArgumentTypeStub(typeName)
        }
    }

    private fun registerArgumentReferencedTypes(sdlTypes: Collection<String>) {
        for (sdlType in sdlTypes) {
            ensureArgumentTypeStubFromSdl(sdlType)
        }
    }

    private fun registerReturnReferencedTypes(sdlTypes: Collection<String>) {
        for (sdlType in sdlTypes) {
            for (typeName in GraphQLTypeInference.extractReferencedBaseTypes(sdlType)) {
                ensureReferencedOutputType(typeName)
            }
        }
    }

    private fun ensureReferencedOutputType(typeName: String) {
        val resolved = resolveTypeAlias(typeName)
        if (resolved in types || resolved in unionTypes) return
        if (GraphQLTypeInference.isBuiltInScalar(resolved)) return
        when (GraphQLTypeInference.stubKindForReferencedType(resolved)) {
            ReferencedTypeKind.SCALAR -> scalarTypes.add(resolved)
            else -> ensureOutputType(resolved)
        }
    }

    private fun ensureOutputTypesForAllFieldReferences() {
        for (fields in types.values) {
            for (field in fields.values) {
                for (typeName in GraphQLTypeInference.extractReferencedBaseTypes(field.returnType)) {
                    ensureReferencedOutputType(typeName)
                }
                for (argType in field.arguments.values) {
                    ensureArgumentTypeStubFromSdl(argType)
                }
            }
        }
    }

    private fun ensureInputStub(typeName: String) {
        inputTypes.getOrPut(typeName) {
            mutableMapOf("_inql_placeholder" to SdlField("String"))
        }
    }

    private fun ensureReferencedTypeStubs() {
        reconcileTypeNamespaces()
        for (outputFields in types.values) {
            for (field in outputFields.values) {
                registerArgumentReferencedTypes(field.arguments.values)
                registerReturnReferencedTypes(listOf(field.returnType))
            }
        }
        for (inputFields in inputTypes.values) {
            for (field in inputFields.values) {
                registerArgumentReferencedTypes(listOf(field.returnType))
            }
        }
        reconcileTypeNamespaces()
    }

    private fun ensureOutputType(name: String) {
        val resolved = resolveTypeAlias(name)
        if (resolved in blockedTypeNames) return
        types.getOrPut(resolved) { mutableMapOf() }
        dropConflictingStubs(resolved)
    }

    private fun dropConflictingStubs(name: String) {
        inputTypes.remove(name)
        if (isUserDefinedType(name)) {
            enumTypes.remove(name)
            scalarTypes.remove(name)
        }
    }

    private fun reserveUnionName(unionName: String) {
        types.remove(unionName)
        inputTypes.remove(unionName)
        enumTypes.remove(unionName)
        scalarTypes.remove(unionName)
    }

    private fun reconcileTypeNamespaces() {
        for (unionName in unionTypes.keys) {
            reserveUnionName(unionName)
        }
        for (outputTypeName in types.keys) {
            dropConflictingStubs(outputTypeName)
        }
        for (inputTypeName in inputTypes.keys.toList()) {
            if (GraphQLTypeInference.isKnownCustomScalar(inputTypeName)) {
                inputTypes.remove(inputTypeName)
                scalarTypes.add(inputTypeName)
                continue
            }
            enumTypes.remove(inputTypeName)
            enumValues.remove(inputTypeName)
            scalarTypes.remove(inputTypeName)
        }
        for (enumTypeName in enumTypes) {
            scalarTypes.remove(enumTypeName)
        }
    }

    private fun isUserDefinedType(name: String): Boolean {
        return !name.startsWith("__") && name !in builtInScalars
    }

    private fun toSdl(): String {
        reconcileTypeNamespaces()
        enumTypes.removeAll(builtInScalars)
        scalarTypes.removeAll(builtInScalars)
        val outputTypeNames = types.keys
        val inputTypeNames = inputTypes.keys
        val emittedTypes = linkedSetOf<String>()
        val sb = StringBuilder()

        for (typeName in scalarTypes.filter {
            it !in outputTypeNames && it !in inputTypeNames && isUserDefinedType(it)
        }.sorted()) {
            if (!emittedTypes.add(typeName)) continue
            sb.append("scalar ").append(typeName).append("\n\n")
        }

        for (typeName in enumTypes.filter {
            it !in outputTypeNames && it !in inputTypeNames && isUserDefinedType(it)
        }.sorted()) {
            if (!emittedTypes.add(typeName)) continue
            sb.append("enum ").append(typeName).append(" {\n")
            val values = enumValues[typeName].orEmpty()
            if (values.isEmpty()) {
                sb.append("  PLACEHOLDER\n")
            } else {
                for (value in values) {
                    sb.append("  ").append(value).append('\n')
                }
            }
            sb.append("}\n\n")
        }

        for ((typeName, fields) in inputTypes.filterKeys { it !in outputTypeNames }.entries.sortedBy { it.key }) {
            if (!emittedTypes.add(typeName)) continue
            sb.append("input ").append(typeName).append(" {\n")
            appendFields(sb, fields)
            sb.append("}\n\n")
        }

        for ((unionName, members) in unionTypes.entries.sortedBy { it.key }) {
            val validMembers = members
                .filter { it != unionName && it in types }
                .sorted()
            if (validMembers.size < 2) continue
            sb.append("union ").append(unionName).append(" = ")
            sb.append(validMembers.joinToString(" | "))
            sb.append("\n\n")
        }

        val unionTypeNames = unionTypes.keys
        val orderedOutputNames = buildList {
            for (name in listOf("Query", "Mutation", "Subscription")) {
                if (name in types && name !in unionTypeNames) add(name)
            }
            addAll(types.keys.filter { it !in rootTypeNames && it !in unionTypeNames }.sorted())
        }

        for (typeName in orderedOutputNames) {
            if (!emittedTypes.add(typeName)) continue
            val fields = types[typeName] ?: continue
            sb.append("type ").append(typeName).append(" {\n")
            appendFields(sb, fields)
            sb.append("}\n\n")
        }

        return sb.toString()
    }

    private fun appendFields(sb: StringBuilder, fields: Map<String, SdlField>) {
        val visibleFields = fields.filterKeys { it != "_inql_placeholder" || fields.size == 1 }
        if (visibleFields.isEmpty()) {
            sb.append("  _inql_placeholder: String\n")
            return
        }
        for ((fieldName, field) in visibleFields) {
            val args = field.arguments.entries.joinToString(", ") { (name, type) ->
                "$name: ${resolveArgTypeForSdl(type)}"
            }
            val argsPart = if (args.isNotEmpty()) "($args)" else ""
            sb.append("  ").append(fieldName).append(argsPart).append(": ")
                .append(applyTypeAliasToSdlType(field.returnType)).append('\n')
        }
    }

    private fun resolveArgTypeForSdl(argType: String): String {
        return applyTypeAliasToSdlType(argType)
    }

    private fun applyTypeAliasToSdlType(sdlType: String): String {
        val base = GraphQLTypeInference.baseTypeName(sdlType)
        val aliased = resolveTypeAlias(base)
        if (aliased == base) return sdlType
        return rewriteBaseType(sdlType, base, aliased)
    }

    private fun rewriteBaseType(sdlType: String, oldBase: String, newBase: String): String {
        if (GraphQLTypeInference.baseTypeName(sdlType) != oldBase) return sdlType
        return Regex("""\b${Regex.escape(oldBase)}\b""").replace(sdlType, newBase)
    }

    private fun unionTypeNameForField(fieldName: String, parentTypeName: String): String {
        val fieldPart = fieldName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        return "${parentTypeName}${fieldPart}Union"
    }

    private fun isUserDefinedOutputType(name: String): Boolean {
        return name !in rootTypeNames && !name.startsWith("__") && name !in builtInScalars
    }

    private fun mergeTypeInto(sourceName: String, targetName: String) {
        if (sourceName == targetName) return
        types[sourceName]?.forEach { (fieldName, field) ->
            mergeField(targetName, fieldName, field.returnType, field.arguments)
        }
        types.remove(sourceName)
        inputTypes[sourceName]?.forEach { (fieldName, field) ->
            registerInputFields(targetName, mapOf(fieldName to field.returnType))
        }
        inputTypes.remove(sourceName)
        enumValues[sourceName]?.let { values ->
            registerEnumValues(targetName, values)
            enumValues.remove(sourceName)
            enumTypes.remove(sourceName)
        }
        scalarTypes.remove(sourceName)
        unionTypes.remove(sourceName)
        rewriteAllTypeReferences(sourceName, targetName)
    }

    private fun renameType(oldName: String, newName: String) {
        if (oldName == newName) return
        if (oldName in builtInScalars || oldName in rootTypeNames) return
        if (newName in builtInScalars) {
            rewriteAllTypeReferences(oldName, newName)
            removeType(oldName)
            return
        }
        types[oldName]?.let { fields ->
            types[newName] = fields
            types.remove(oldName)
        }
        inputTypes[oldName]?.let { fields ->
            inputTypes[newName] = fields
            inputTypes.remove(oldName)
        }
        if (oldName in enumTypes) {
            enumTypes.remove(oldName)
            enumTypes.add(newName)
        }
        enumValues[oldName]?.let { values ->
            enumValues[newName] = values
            enumValues.remove(oldName)
        }
        if (oldName in scalarTypes) {
            scalarTypes.remove(oldName)
            scalarTypes.add(newName)
        }
        unionTypes[oldName]?.let { members ->
            unionTypes[newName] = members
            unionTypes.remove(oldName)
        }
        for (members in unionTypes.values) {
            if (members.remove(oldName)) {
                members.add(newName)
            }
        }
        rewriteAllTypeReferences(oldName, newName)
    }

    fun removeType(typeName: String) {
        val alias = resolveTypeAlias(typeName)
        if (alias != typeName) {
            rewriteAllTypeReferences(typeName, alias)
        }
        types.remove(typeName)
        inputTypes.remove(typeName)
        enumTypes.remove(typeName)
        enumValues.remove(typeName)
        scalarTypes.remove(typeName)
        unionTypes.remove(typeName)
    }

    private fun removePlaceholderFields() {
        val placeholderNames = setOf("_inql_placeholder")
        for (fields in types.values) {
            fields.keys.removeAll(placeholderNames)
        }
        for (fields in inputTypes.values) {
            fields.keys.removeAll(placeholderNames)
        }
        for (values in enumValues.values) {
            values.remove("PLACEHOLDER")
            values.remove("_inql_placeholder")
        }
    }

    private fun applyFieldTypeOverrides(typeName: String, fields: Map<String, String>) {
        for ((fieldName, fieldType) in fields) {
            types[typeName]?.get(fieldName)?.returnType = fieldType
            inputTypes[typeName]?.get(fieldName)?.let { existing ->
                existing.returnType = fieldType
            } ?: run {
                inputTypes.getOrPut(typeName) { mutableMapOf() }[fieldName] = SdlField(fieldType)
            }
        }
    }

    private fun applyEnumValueOverrides(overrides: Map<String, List<String>>) {
        for ((enumTypeName, values) in overrides) {
            if (values.isEmpty()) continue
            types.remove(enumTypeName)
            unionTypes.remove(enumTypeName)
            scalarTypes.remove(enumTypeName)
            inputTypes.remove(enumTypeName)
            replaceEnumValues(enumTypeName, values)
        }
    }

    private fun applyInputEnumFieldOverrides(overrides: Map<String, Map<String, List<String>>>) {
        for ((inputTypeName, fieldMap) in overrides) {
            for ((fieldName, values) in fieldMap) {
                applyInputEnumFieldOverride(inputTypeName, fieldName, values)
            }
        }
    }

    private fun applyInputEnumFieldOverride(
        inputTypeName: String,
        fieldName: String,
        values: List<String>,
    ) {
        if (values.isEmpty()) return
        val enumName = InputEnumTypeMatching.preferredEnumNameForInputField(inputTypeName, fieldName)
        // Input enum corrections take precedence over an inferred output type with the same name.
        types.remove(enumName)
        unionTypes.remove(enumName)
        scalarTypes.remove(enumName)
        replaceEnumValues(enumName, values)
        val fields = inputTypes.getOrPut(inputTypeName) { mutableMapOf() }
        val existing = fields[fieldName]
        val enumSdlType = preserveNullability(existing?.returnType, enumName, defaultNonNull = true)
        if (existing != null) {
            existing.returnType = enumSdlType
        } else {
            fields[fieldName] = SdlField(enumSdlType)
        }
        registerArgumentReferencedTypes(listOf(enumSdlType))
    }

    private fun preserveNullability(
        existingType: String?,
        newBase: String,
        defaultNonNull: Boolean = false,
    ): String {
        val required = existingType?.endsWith("!") == true || (existingType == null && defaultNonNull)
        return if (required) "$newBase!" else newBase
    }

    private fun applyArgumentTypeOverrides(
        parentType: String,
        fieldMap: Map<String, Map<String, String>>,
    ) {
        val resolvedParent = resolveConnectionNodeOverrideParent(parentType) ?: parentType
        for ((fieldName, argMap) in fieldMap) {
            val existingReturn = types[resolvedParent]?.get(fieldName)?.returnType ?: "String"
            mergeField(
                parentType = resolvedParent,
                fieldName = fieldName,
                returnType = existingReturn,
                arguments = argMap,
            )
            for (argType in argMap.values) {
                ensureArgumentTypeStubFromSdl(argType)
            }
        }
    }

    private fun resolveConnectionNodeOverrideParent(parentType: String): String? {
        if (types.containsKey(parentType)) return parentType
        for ((holderType, fields) in types) {
            for ((fieldName, field) in fields) {
                val connectionType = GraphQLTypeInference.baseTypeName(field.returnType)
                if (!connectionType.endsWith("Connection")) continue
                val wiredNodeType = connectionWiredNodeType(connectionType) ?: continue
                val synthetic = syntheticConnectionNodeTypeName(holderType, fieldName)
                if (parentType == synthetic || parentType == wiredNodeType) {
                    return wiredNodeType
                }
            }
        }
        return null
    }

    private fun rewriteAllTypeReferences(oldBase: String, newBase: String) {
        for (fields in types.values) {
            for (field in fields.values) {
                field.returnType = rewriteAllBases(field.returnType, oldBase, newBase)
                for ((argName, argType) in field.arguments.toMap()) {
                    field.arguments[argName] = rewriteAllBases(argType, oldBase, newBase)
                }
            }
        }
        for (fields in inputTypes.values) {
            for (field in fields.values) {
                field.returnType = rewriteAllBases(field.returnType, oldBase, newBase)
            }
        }
        for ((unionName, members) in unionTypes.toMap()) {
            if (members.remove(oldBase)) {
                members.add(newBase)
                unionTypes[unionName] = members
            }
        }
    }

    private fun rewriteAllBases(sdlType: String, oldBase: String, newBase: String): String {
        return Regex("""\b${Regex.escape(oldBase)}\b""").replace(sdlType, newBase)
    }

    private fun graphQLTypeToSdl(type: GraphQLType): String {
        return when (type) {
            is graphql.schema.GraphQLNonNull -> "${graphQLTypeToSdl(type.wrappedType)}!"
            is graphql.schema.GraphQLList -> "[${graphQLTypeToSdl(type.wrappedType)}]"
            is GraphQLNamedType -> type.name
            else -> "String"
        }
    }
}
