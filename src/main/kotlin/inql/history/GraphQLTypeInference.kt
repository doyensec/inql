package inql.history

import graphql.language.*
import java.util.LinkedHashSet

internal enum class ReferencedTypeKind {
    INPUT,
    ENUM,
    SCALAR,
}

internal data class ValueInferenceContext(
    val operationType: String = "query",
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
    private val intFieldNames = setOf(
        "count", "total", "limit", "offset", "page", "size", "age", "year",
        "length", "num", "number", "quantity", "index", "timestamp",
    )
    private val enumFieldNames = setOf(
        "status", "type", "category", "role", "state", "kind", "mode", "level",
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
    ): String {
        return when (value) {
            is VariableReference -> variableTypes[value.name] ?: "String"
            is StringValue -> "String"
            is IntValue -> "Int"
            is FloatValue -> "Float"
            is BooleanValue -> "Boolean"
            is EnumValue -> inferEnumValueType(value, context)
            is NullValue -> "String"
            is ArrayValue -> inferListValueType(value, variableTypes, context)
            is ObjectValue -> inferObjectValueType(value, variableTypes, context)
            else -> "String"
        }
    }

    fun extractObjectFields(
        objectValue: ObjectValue,
        variableTypes: Map<String, String>,
        inputTypeName: String,
        context: ValueInferenceContext,
    ): Map<String, String> {
        return objectValue.objectFields.associate { objectField ->
            val fieldContext = context.copy(
                inputTypeName = inputTypeName,
                objectFieldName = objectField.name,
            )
            objectField.name to inferValueType(objectField.value, variableTypes, fieldContext)
        }
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

    fun inferScalarFromFieldName(fieldName: String): String {
        if (fieldName == "id" || fieldName.endsWith("Id")) return "ID"
        val lower = fieldName.lowercase()
        if (lower.startsWith("is") || lower.startsWith("has") || lower.startsWith("can")) return "Boolean"
        if (lower in intFieldNames || lower.endsWith("count") || lower.endsWith("total")) return "Int"
        return "String"
    }

    fun inferReturnTypeFromResponse(fieldResponse: Any?, fieldName: String): String? {
        return when (fieldResponse) {
            is List<*>, is org.json.JSONArray -> {
                val elements = when (fieldResponse) {
                    is List<*> -> fieldResponse
                    is org.json.JSONArray -> (0 until fieldResponse.length()).map { index -> fieldResponse.opt(index) }
                    else -> emptyList()
                }
                if (elements.isEmpty()) return "[String]"
                val merged = elements
                    .map { inferScalarFromJson(it) ?: inferScalarFromFieldName(fieldName) }
                    .reduce { left, right -> mergeSdlTypes(left, right) }
                wrapListType(merged)
            }
            else -> inferScalarFromJson(fieldResponse) ?: inferScalarFromFieldName(fieldName)
        }
    }

    fun baseTypeName(type: String): String {
        return type.replace(Regex("""[\[\]!]"""), "")
    }

    fun isBuiltInScalar(typeName: String): Boolean = typeName in builtInScalars

    fun extractReferencedBaseTypes(sdlType: String): Set<String> {
        val base = peelTypeModifiers(sdlType)
        if (base.isEmpty() || base in builtInScalars) return emptySet()
        if (!base.matches(Regex("""^[A-Za-z_][A-Za-z0-9_]*$"""))) return emptySet()
        return setOf(base)
    }

    fun stubKindForReferencedType(typeName: String): ReferencedTypeKind? {
        return when {
            typeName.endsWith("Result", ignoreCase = true) -> null
            typeName.endsWith("Input", ignoreCase = true) -> ReferencedTypeKind.INPUT
            typeName in knownCustomScalars -> ReferencedTypeKind.SCALAR
            typeName.endsWith("Enum", ignoreCase = true) -> ReferencedTypeKind.ENUM
            typeName.endsWith("Status", ignoreCase = true) -> ReferencedTypeKind.ENUM
            typeName.endsWith("Type", ignoreCase = true) -> ReferencedTypeKind.ENUM
            typeName.endsWith("Category", ignoreCase = true) -> ReferencedTypeKind.ENUM
            typeName.endsWith("Role", ignoreCase = true) -> ReferencedTypeKind.ENUM
            typeName.endsWith("State", ignoreCase = true) -> ReferencedTypeKind.ENUM
            else -> ReferencedTypeKind.INPUT
        }
    }

    private fun inferObjectValueType(
        objectValue: ObjectValue,
        variableTypes: Map<String, String>,
        context: ValueInferenceContext,
    ): String {
        return resolveInputTypeName(context)
    }

    private fun inferEnumValueType(value: EnumValue, context: ValueInferenceContext): String {
        val enumName = enumTypeNameForField(context.objectFieldName, context.inputTypeName)
        context.enumValues?.getOrPut(enumName) { linkedSetOf() }?.add(value.name)
        return enumName
    }

    private fun resolveInputTypeName(context: ValueInferenceContext): String {
        context.argumentName?.let { argumentName ->
            context.argumentTypeHints[argumentName]?.let { hintedType ->
                return hintedType.trim()
            }
        }

        if (context.inputTypeName != null && context.objectFieldName != null) {
            return nestedInputTypeName(context.inputTypeName, context.objectFieldName)
        }

        val fieldBase = context.parentFieldName?.toPascalCase() ?: "Unknown"
        val argumentName = context.argumentName

        val baseName = when {
            context.operationType == "mutation" && argumentName == "input" ->
                "${fieldBase}MutationInput"
            argumentName == "input" ->
                "${fieldBase}Input"
            !argumentName.isNullOrBlank() ->
                "${fieldBase}${argumentName.toPascalCase()}Input"
            else ->
                "${fieldBase}Input"
        }

        return if (context.inputTypeName == null && context.argumentName != null) {
            ensureNonNullSdlType(baseName)
        } else {
            baseName
        }
    }

    fun ensureNonNullSdlType(type: String): String {
        val trimmed = type.trim()
        return if (trimmed.endsWith("!")) trimmed else "$trimmed!"
    }

    private fun nestedInputTypeName(parentInputType: String, fieldName: String): String {
        val parentBase = parentInputType.removeSuffix("Input")
        return "${parentBase}${fieldName.toPascalCase()}Input"
    }

    private fun enumTypeNameForField(fieldName: String?, parentInputType: String?): String {
        if (fieldName.isNullOrBlank()) return "String"
        val parentBase = parentInputType
            ?.removeSuffix("Input")
            ?.removeSuffix("Mutation")
            ?: fieldName.toPascalCase()
        return when (fieldName.lowercase()) {
            in enumFieldNames -> "${parentBase}${fieldName.toPascalCase()}"
            else -> "${fieldName.toPascalCase()}Enum"
        }
    }

    private fun inferListValueType(
        value: ArrayValue,
        variableTypes: Map<String, String>,
        context: ValueInferenceContext,
    ): String {
        if (value.values.isEmpty()) return "[String]"
        val mergedElement = value.values
            .map { inferValueType(it, variableTypes, context) }
            .reduce { left, right -> mergeSdlTypes(left, right) }
        return wrapListType(mergedElement)
    }

    private fun inferListTypeFromJson(value: Any?): String? {
        val elements = when (value) {
            is List<*> -> value
            is org.json.JSONArray -> (0 until value.length()).map { index -> value.opt(index) }
            else -> return null
        }
        if (elements.isEmpty()) return "[String]"
        val merged = elements
            .mapNotNull { inferScalarFromJson(it) }
            .reduceOrNull { left, right -> mergeSdlTypes(left, right) }
            ?: return "[String]"
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

    private fun String.toPascalCase(): String {
        if (isBlank()) return this
        return replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    }
}
