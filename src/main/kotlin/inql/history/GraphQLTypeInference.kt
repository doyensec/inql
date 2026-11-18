package inql.history

import graphql.language.*
import java.util.LinkedHashSet

internal enum class ReferencedTypeKind {
    INPUT,
    ENUM,
    SCALAR,
}

internal data class ValueInferenceContext(
    /** GraphQL output type that declares [parentFieldName] (e.g. DiscoveryCollections for queryCollections). */
    val parentOutputTypeName: String? = null,
    val parentFieldName: String? = null,
    val argumentName: String? = null,
    val inputTypeName: String? = null,
    val objectFieldName: String? = null,
    val argumentTypeHints: Map<String, String> = emptyMap(),
    val enumValues: MutableMap<String, LinkedHashSet<String>>? = null,
)

internal object GraphQLTypeInference {
    private val builtInScalars = setOf("String", "Int", "Float", "Boolean", "ID")
    private val knownCustomScalars = setOf(
        "Date", "DateTime", "Time", "JSON", "JSONObject", "UUID", "Url", "URI",
        "BigInt", "Long", "Upload", "Void",
    )
    fun typeToSdl(type: Type<*>): String {
        return when (type) {
            is NonNullType -> "${typeToSdl(type.type)}!"
            is ListType -> "[${typeToSdl(type.type)}]"
            is TypeName -> type.name
            else -> "String"
        }
    }

    fun buildVariableTypeMap(operation: OperationDefinition): Map<String, String> {
        return operation.variableDefinitions.associate { variableDefinition ->
            variableDefinition.name to typeToSdl(variableDefinition.type)
        }
    }

    fun inferValueType(
        value: Value<*>,
        variableTypes: Map<String, String>,
        context: ValueInferenceContext = ValueInferenceContext(),
    ): String? {
        return when (value) {
            is VariableReference -> variableTypes[value.name]
            is StringValue -> "String"
            is IntValue -> "Int"
            is FloatValue -> "Float"
            is BooleanValue -> "Boolean"
            is EnumValue -> inferEnumValueType(value, context)
            is NullValue -> null
            is ArrayValue -> inferListValueType(value, variableTypes, context)
            is ObjectValue -> inferObjectValueType(context)
            else -> null
        }
    }

    fun extractObjectFields(
        objectValue: ObjectValue,
        variableTypes: Map<String, String>,
        inputTypeName: String,
        context: ValueInferenceContext,
        inlineInputFields: MutableMap<String, MutableMap<String, String>>? = null,
    ): Map<String, String> {
        val fields = linkedMapOf<String, String>()
        for (objectField in objectValue.objectFields) {
            val fieldContext = context.copy(
                inputTypeName = inputTypeName,
                objectFieldName = objectField.name,
            )
            when (val value = objectField.value) {
                is ObjectValue -> {
                    val nestedTypeName = syntheticNestedInputFieldType(inputTypeName, objectField.name)
                    val nestedFields = extractObjectFields(
                        value,
                        variableTypes,
                        nestedTypeName,
                        fieldContext.copy(inputTypeName = nestedTypeName),
                        inlineInputFields,
                    )
                    if (nestedFields.isNotEmpty()) {
                        inlineInputFields?.getOrPut(nestedTypeName) { linkedMapOf() }?.let { bucket ->
                            for ((name, type) in nestedFields) {
                                bucket[name] = mergeSdlTypes(bucket[name], type)
                            }
                        }
                        fields[objectField.name] = mergeSdlTypes(
                            fields[objectField.name],
                            ensureNonNullSdlType(nestedTypeName),
                        )
                    }
                }
                else -> {
                    inferValueType(value, variableTypes, fieldContext)?.let { fieldType ->
                        fields[objectField.name] = mergeSdlTypes(fields[objectField.name], fieldType)
                    }
                }
            }
        }
        return fields
    }

    fun mergeSdlTypes(current: String?, incoming: String): String {
        if (current.isNullOrBlank()) return incoming
        if (current == incoming) return current

        val currentBase = baseTypeName(current)
        val incomingBase = baseTypeName(incoming)

        if (currentBase == incomingBase) {
            return if (typeSpecificity(incoming) >= typeSpecificity(current)) incoming else current
        }
        if (currentBase == "String" && incomingBase != "String") return incoming
        if (incomingBase == "String" && currentBase != "String") return current

        return if (typeSpecificity(incoming) > typeSpecificity(current)) incoming else current
    }

    /**
     * Merges argument types without collapsing unrelated input object names that happen to
     * share a field name across different parent types (e.g. paging on latestPostsConnection).
     */
    fun mergeArgumentSdlTypes(
        current: String?,
        incoming: String,
        parentType: String,
        fieldName: String,
        argumentName: String,
    ): String {
        if (current.isNullOrBlank()) return incoming
        val currentBase = baseTypeName(current)
        val incomingBase = baseTypeName(incoming)
        if (currentBase == incomingBase) {
            return mergeSdlTypes(current, incoming)
        }
        if (currentBase in builtInScalars || incomingBase in builtInScalars) {
            return mergeSdlTypes(current, incoming)
        }
        val synthetic = syntheticInputTypeForArgument(parentType, fieldName, argumentName)
        return when {
            currentBase == synthetic -> current
            incomingBase == synthetic -> incoming
            else -> current
        }
    }

    fun inferScalarFromJson(value: Any?): String? {
        return when (value) {
            null -> null
            is Boolean -> "Boolean"
            is Int, is Long -> "Int"
            is Float, is Double -> {
                val numeric = (value as Number).toDouble()
                if (numeric % 1.0 == 0.0) "Int" else "Float"
            }
            is Number -> {
                val numeric = value.toDouble()
                if (numeric % 1.0 == 0.0) "Int" else "Float"
            }
            is String -> inferScalarFromStringValue(value)
            is List<*>, is org.json.JSONArray -> inferListTypeFromJson(value)
            else -> null
        }
    }

    fun inferScalarFromStringValue(value: String): String {
        if (value.equals("true", ignoreCase = true) || value.equals("false", ignoreCase = true)) {
            return "Boolean"
        }
        if (value.matches(Regex("""^-?\d+$"""))) return "Int"
        if (value.matches(Regex("""^-?\d+\.\d+$"""))) return "Float"
        if (looksLikeId(value)) return "ID"
        return "String"
    }

    fun inferReturnTypeFromResponse(fieldResponse: Any?): String? {
        return inferScalarFromJson(fieldResponse)
    }

    fun baseTypeName(type: String): String {
        return type.replace(Regex("""[\[\]!]"""), "")
    }

    fun isBuiltInScalar(typeName: String): Boolean = typeName in builtInScalars

    fun isKnownCustomScalar(typeName: String): Boolean = typeName in knownCustomScalars

    fun extractReferencedBaseTypes(sdlType: String): Set<String> {
        val base = peelTypeModifiers(sdlType)
        if (base.isEmpty() || base in builtInScalars) return emptySet()
        if (!base.matches(Regex("""^[A-Za-z_][A-Za-z0-9_]*$"""))) return emptySet()
        return setOf(base)
    }

    fun stubKindForReferencedType(typeName: String): ReferencedTypeKind? {
        return when {
            typeName in knownCustomScalars -> ReferencedTypeKind.SCALAR
            else -> null
        }
    }

    /**
     * GraphQL arguments may only be scalars, enums, or input objects. When a custom type name is
     * evidenced in a variable declaration or argument reference, stub it so generated SDL parses.
     */
    fun argumentStubKind(
        typeName: String,
        enumValues: Map<String, Collection<String>> = emptyMap(),
    ): ReferencedTypeKind {
        if (typeName in knownCustomScalars) return ReferencedTypeKind.SCALAR
        if (enumValues[typeName]?.isNotEmpty() == true) return ReferencedTypeKind.ENUM
        if (typeName.endsWith("Enum") || typeName.endsWith("Sizes")) return ReferencedTypeKind.ENUM
        return ReferencedTypeKind.INPUT
    }

    fun syntheticInputTypeForArgument(
        parentOutputTypeName: String,
        fieldName: String,
        argumentName: String,
    ): String {
        val fieldPart = fieldName.toGraphQLPascalCase()
        return when (argumentName) {
            "input" -> "${parentOutputTypeName}${fieldPart}Input"
            else -> "${parentOutputTypeName}${fieldPart}${argumentName.toGraphQLPascalCase()}Input"
        }
    }

    fun syntheticNestedInputFieldType(parentInputTypeName: String, fieldName: String): String {
        return "${parentInputTypeName}${fieldName.toGraphQLPascalCase()}"
    }

    private fun inferObjectValueType(context: ValueInferenceContext): String? {
        resolveInputTypeName(context)?.let { return it }
        val parentType = context.parentOutputTypeName ?: return null
        val fieldName = context.parentFieldName ?: return null
        val argumentName = context.argumentName ?: return null
        return syntheticInputTypeForArgument(parentType, fieldName, argumentName)
    }

    private fun inferEnumValueType(value: EnumValue, context: ValueInferenceContext): String {
        context.argumentName?.let { argumentName ->
            context.argumentTypeHints[argumentName]?.let { hintedType ->
                val enumName = baseTypeName(hintedType)
                context.enumValues?.getOrPut(enumName) { linkedSetOf() }?.add(value.name)
                return hintedType
            }
        }
        context.inputTypeName?.let { parentInput ->
            context.objectFieldName?.let { fieldName ->
                val enumName = "${parentInput.removeSuffix("Input")}${fieldName.toGraphQLPascalCase()}"
                context.enumValues?.getOrPut(enumName) { linkedSetOf() }?.add(value.name)
            }
        }
        return "String"
    }

    private fun resolveInputTypeName(context: ValueInferenceContext): String? {
        context.argumentName?.let { argumentName ->
            context.argumentTypeHints[argumentName]?.let { hintedType ->
                return hintedType.trim()
            }
        }
        return null
    }

    fun ensureNonNullSdlType(type: String): String {
        val trimmed = type.trim()
        return if (trimmed.endsWith("!")) trimmed else "$trimmed!"
    }

    private fun inferListValueType(
        value: ArrayValue,
        variableTypes: Map<String, String>,
        context: ValueInferenceContext,
    ): String? {
        if (value.values.isEmpty()) return null
        val mergedElement = value.values
            .mapNotNull { inferValueType(it, variableTypes, context) }
            .reduceOrNull { left, right -> mergeSdlTypes(left, right) }
            ?: return null
        return wrapListType(mergedElement)
    }

    private fun inferListTypeFromJson(value: Any?): String? {
        val elements = when (value) {
            is List<*> -> value
            is org.json.JSONArray -> (0 until value.length()).map { index -> value.opt(index) }
            else -> return null
        }
        if (elements.isEmpty()) return null
        val merged = elements
            .mapNotNull { inferScalarFromJson(it) }
            .reduceOrNull { left, right -> mergeSdlTypes(left, right) }
            ?: return null
        return wrapListType(merged)
    }

    private fun wrapListType(elementType: String): String {
        val nullableElement = elementType.removeSuffix("!")
        val listType = "[$nullableElement]"
        return if (elementType.endsWith("!")) "$listType!" else listType
    }

    private fun looksLikeId(value: String): Boolean {
        if (value.length in 8..128 && value.matches(Regex("""^[A-Za-z0-9_-]+$"""))) {
            return value.any { it.isDigit() }
        }
        return false
    }

    private fun typeSpecificity(type: String): Int {
        var score = 0
        if (baseTypeName(type) in builtInScalars && baseTypeName(type) != "String") {
            score += 10
        } else if (baseTypeName(type) != "String") {
            score += 5
        }
        score += type.count { it == '!' } * 2
        score += type.count { it == '[' }
        return score
    }

    private fun peelTypeModifiers(type: String): String {
        var current = type.trim()
        while (current.endsWith('!')) {
            current = current.dropLast(1)
        }
        if (current.startsWith('[') && current.endsWith(']')) {
            return peelTypeModifiers(current.substring(1, current.length - 1))
        }
        return current
    }
}
