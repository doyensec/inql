package inql.history

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

/**
 * Builds partial GraphQL schemas via SDL text to avoid graphql-java type reference casting issues.
 */
internal class SdlTypeRegistry {
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

    fun addFields(parentType: String, fieldNodes: List<QueryAstToSchema.FieldNode>) {
        ensureOutputType(parentType)
        for (field in fieldNodes) {
            when {
                field.inlineFragments.isNotEmpty() -> {
                    val unionName = unionTypeNameForField(field.name)
                    for ((memberType, memberFields) in field.inlineFragments) {
                        addFields(memberType, memberFields)
                        addUnionMember(unionName, memberType)
                    }
                    mergeField(parentType, field.name, unionName, field.arguments)
                }

                field.children.isNotEmpty() -> {
                    val childType = fieldNameToTypeName(field.name, parentType)
                    addFields(childType, field.children)
                    mergeField(parentType, field.name, childType, field.arguments)
                }

                field.hasSubselection -> {
                    val childType = fieldNameToTypeName(field.name, parentType)
                    ensureOutputType(childType)
                    mergeField(parentType, field.name, childType, field.arguments)
                }

                else -> {
                    val returnType = field.scalarReturnType
                        ?: GraphQLTypeInference.inferScalarFromFieldName(field.name)
                    mergeField(parentType, field.name, returnType, field.arguments)
                }
            }
        }
    }

    fun registerInputFields(typeName: String, fields: Map<String, String>) {
        if (fields.isEmpty()) return
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
        registerReferencedTypes(fields.values)
        for ((fieldName, fieldType) in fields) {
            registerEnumValuesFromField(fieldName, fieldType)
        }
    }

    fun registerEnumValues(typeName: String, values: Collection<String>) {
        if (values.isEmpty()) return
        enumTypes.add(typeName)
        val bucket = enumValues.getOrPut(typeName) { linkedSetOf() }
        bucket.addAll(values.filter { it != "PLACEHOLDER" && it != "_inql_placeholder" })
        if (bucket.isNotEmpty()) {
            bucket.remove("PLACEHOLDER")
            bucket.remove("_inql_placeholder")
        }
    }

    fun applyArgumentTypeHints(hints: List<GraphQLErrorTypeHints.ArgumentTypeHint>) {
        for (hint in hints) {
            val fields = types[hint.rootType] ?: continue
            val field = fields[hint.fieldName] ?: continue
            field.arguments[hint.argumentName] = GraphQLTypeInference.mergeSdlTypes(
                field.arguments[hint.argumentName],
                hint.expectedType,
            )
            registerReferencedTypes(listOf(hint.expectedType))
        }
    }

    fun addUnionMember(unionName: String, memberType: String) {
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
            registerReferencedTypes(listOf(fieldType))
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

    fun toSchema(): GraphQLSchema? {
        ensureQueryRoot()
        ensureReferencedTypeStubs()
        return try {
            val sdl = toSdl()
            val registry = SchemaParser().parse(sdl)
            SchemaGenerator().makeExecutableSchema(
                registry,
                SchemaInspectionRuntimeWiring.build(registry),
            )
        } catch (e: SchemaProblem) {
            Logger.debug("Failed to parse generated SDL schema: ${e.message}")
            null
        } catch (e: Exception) {
            Logger.debug("Failed to build schema from SDL: ${e.message}")
            null
        }
    }

    private fun mergeField(
        parentType: String,
        fieldName: String,
        returnType: String,
        arguments: Map<String, String>,
    ) {
        ensureOutputType(parentType)
        val fields = types[parentType]!!
        val existing = fields[fieldName]
        if (existing == null) {
            fields[fieldName] = SdlField(returnType, arguments.toMutableMap())
        } else {
            arguments.forEach { (name, type) ->
                existing.arguments[name] = GraphQLTypeInference.mergeSdlTypes(existing.arguments[name], type)
            }
            existing.returnType = GraphQLTypeInference.mergeSdlTypes(existing.returnType, returnType)
        }
        registerReferencedTypes(arguments.values)
        registerReferencedTypes(listOf(returnType))
    }

    private fun registerReferencedTypes(sdlTypes: Collection<String>) {
        for (sdlType in sdlTypes) {
            for (typeName in GraphQLTypeInference.extractReferencedBaseTypes(sdlType)) {
                if (typeName in types || typeName in unionTypes) continue
                if (GraphQLTypeInference.isBuiltInScalar(typeName)) continue
                when (GraphQLTypeInference.stubKindForReferencedType(typeName)) {
                    ReferencedTypeKind.INPUT -> {
                        if (typeName !in inputTypes) ensureInputStub(typeName)
                    }
                    ReferencedTypeKind.ENUM -> {
                        if (typeName !in types) enumTypes.add(typeName)
                    }
                    ReferencedTypeKind.SCALAR -> {
                        if (typeName !in types) scalarTypes.add(typeName)
                    }
                    null -> continue
                }
            }
        }
    }

    private fun registerEnumValuesFromField(fieldName: String, fieldType: String) {
        val baseType = GraphQLTypeInference.baseTypeName(fieldType)
        if (GraphQLTypeInference.stubKindForReferencedType(baseType) != ReferencedTypeKind.ENUM) return
        enumTypes.add(baseType)
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
                registerReferencedTypes(field.arguments.values)
                registerReferencedTypes(listOf(field.returnType))
            }
        }
        reconcileTypeNamespaces()
    }

    private fun ensureOutputType(name: String) {
        types.getOrPut(name) { mutableMapOf() }
        dropConflictingStubs(name)
    }

    private fun dropConflictingStubs(name: String) {
        inputTypes.remove(name)
        enumTypes.remove(name)
        scalarTypes.remove(name)
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
    }

    private fun isUserDefinedType(name: String): Boolean {
        return !name.startsWith("__") && name !in builtInScalars
    }

    private fun toSdl(): String {
        reconcileTypeNamespaces()
        val outputTypeNames = types.keys
        val sb = StringBuilder()

        for (typeName in scalarTypes.filter { it !in outputTypeNames }.sorted()) {
            sb.append("scalar ").append(typeName).append("\n\n")
        }

        for (typeName in enumTypes.filter { it !in outputTypeNames }.sorted()) {
            sb.append("enum ").append(typeName).append(" {\n")
            val values = enumValues[typeName].orEmpty()
            if (values.isEmpty()) {
                sb.append("  PLACEHOLDER\n")
            } else {
                for (value in values.sorted()) {
                    sb.append("  ").append(value).append('\n')
                }
            }
            sb.append("}\n\n")
        }

        for ((typeName, fields) in inputTypes.filterKeys { it !in outputTypeNames }.entries.sortedBy { it.key }) {
            sb.append("input ").append(typeName).append(" {\n")
            appendFields(sb, fields)
            sb.append("}\n\n")
        }

        for ((unionName, members) in unionTypes.entries.sortedBy { it.key }) {
            if (members.isEmpty()) continue
            sb.append("union ").append(unionName).append(" = ")
            sb.append(members.sorted().joinToString(" | "))
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
            sb.append("  ").append(fieldName).append(argsPart).append(": ").append(field.returnType).append('\n')
        }
    }

    private fun resolveArgTypeForSdl(argType: String): String {
        val base = GraphQLTypeInference.baseTypeName(argType)
        if (base !in types || base in inputTypes) return argType
        val inputAlias = inputAliasName(base)
        ensureInputStub(inputAlias)
        return rewriteBaseType(argType, base, inputAlias)
    }

    private fun inputAliasName(outputTypeName: String): String {
        return if (outputTypeName.endsWith("Input", ignoreCase = true)) {
            "${outputTypeName}Arg"
        } else {
            "${outputTypeName}Input"
        }
    }

    private fun rewriteBaseType(sdlType: String, oldBase: String, newBase: String): String {
        if (GraphQLTypeInference.baseTypeName(sdlType) != oldBase) return sdlType
        return Regex("""\b${Regex.escape(oldBase)}\b""").replace(sdlType, newBase)
    }

    private fun unionTypeNameForField(fieldName: String): String {
        val base = fieldName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        return if (base.endsWith("Result")) base else "${base}Result"
    }

    private fun fieldNameToTypeName(fieldName: String, parentTypeName: String): String {
        var name = fieldName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        if (name.endsWith("s") && name.length > 1) {
            name = name.dropLast(1)
        }
        if (name == parentTypeName) {
            name = "${name}Item"
        }
        if (name in unionTypes) {
            name = "${name}Item"
        }
        return name
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
