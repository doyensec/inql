package inql.history

import graphql.language.*

internal enum class ReferencedTypeKind {
    INPUT,
    ENUM,
    SCALAR,
}

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

    fun inferValueType(value: Value<*>, variableTypes: Map<String, String>): String {
        return when (value) {
            is VariableReference -> variableTypes[value.name] ?: "String"
            is StringValue -> "String"
            is IntValue -> "Int"
            is FloatValue -> "Float"
            is BooleanValue -> "Boolean"
            is EnumValue -> "String"
            is NullValue -> "String"
            is ArrayValue -> inferListValueType(value, variableTypes)
            is ObjectValue -> "String"
            else -> "String"
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
            is String -> inferScalarFromString(value)
            else -> null
        }
    }

    fun inferScalarFromFieldName(fieldName: String): String {
        if (fieldName == "id" || fieldName.endsWith("Id")) return "ID"
        val lower = fieldName.lowercase()
        if (lower.startsWith("is") || lower.startsWith("has") || lower.startsWith("can")) return "Boolean"
        if (lower in intFieldNames || lower.endsWith("count") || lower.endsWith("total")) return "Int"
        return "String"
    }

    private fun inferListValueType(value: ArrayValue, variableTypes: Map<String, String>): String {
        if (value.values.isEmpty()) return "[String]"
        val mergedElement = value.values
            .map { inferValueType(it, variableTypes) }
            .reduce { left, right -> mergeSdlTypes(left, right) }
        return wrapListType(mergedElement)
    }

    private fun wrapListType(elementType: String): String {
        val nullableElement = elementType.removeSuffix("!")
        val listType = "[$nullableElement]"
        return if (elementType.endsWith("!")) "$listType!" else listType
    }

    private fun inferScalarFromString(value: String): String {
        if (value.equals("true", ignoreCase = true) || value.equals("false", ignoreCase = true)) {
            return "Boolean"
        }
        if (value.matches(Regex("""^-?\d+$"""))) return "Int"
        if (value.matches(Regex("""^-?\d+\.\d+$"""))) return "Float"
        if (looksLikeId(value)) return "ID"
        return "String"
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
            else -> ReferencedTypeKind.INPUT
        }
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
