package inql.history

import org.json.JSONArray
import org.json.JSONObject

/**
 * Infers GraphQL SDL types from JSON variable values and response payloads.
 */
internal object JsonValueTypeInference {
    fun inferSdlType(value: Any?): String {
        return when (value) {
            null -> "String"
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
            is String -> GraphQLTypeInference.inferScalarFromStringValue(value)
            is Map<*, *> -> inferObjectTypeName(value)
            is JSONObject -> inferObjectTypeName(jsonObjectToMap(value))
            is List<*>, is JSONArray -> inferListType(value)
            else -> "String"
        }
    }

    fun extractInputFields(value: Any?, parentInputType: String? = null): Map<String, String> {
        val objectValue = asObjectMap(value) ?: return emptyMap()
        return objectValue.mapValues { (fieldName, fieldValue) ->
            inferFieldType(fieldName, fieldValue, parentInputType)
        }
    }

    fun applyVariableValues(
        registry: SdlTypeRegistry,
        variables: Map<String, Any?>,
        variableTypes: Map<String, String>,
    ) {
        for ((name, value) in variables) {
            if (value == null) continue
            val declaredType = variableTypes[name] ?: continue
            registerValueShape(registry, declaredType, value)
        }
    }

    private fun registerValueShape(registry: SdlTypeRegistry, declaredType: String, value: Any?) {
        val baseType = GraphQLTypeInference.baseTypeName(declaredType)
        when (value) {
            is List<*>, is JSONArray -> {
                val elements = asList(value)
                val elementDeclaredType = listElementType(declaredType)
                for (element in elements) {
                    if (elementDeclaredType != null) {
                        registerValueShape(registry, elementDeclaredType, element)
                    } else {
                        registerObjectFields(registry, baseType, element)
                    }
                }
            }
            else -> registerObjectFields(registry, baseType, value)
        }
    }

    private fun registerObjectFields(registry: SdlTypeRegistry, typeName: String, value: Any?) {
        val objectValue = asObjectMap(value) ?: return
        val fields = extractInputFields(value, typeName)
        if (fields.isNotEmpty()) {
            registry.registerInputFields(typeName, fields)
        }
        for ((fieldName, fieldValue) in objectValue) {
            if (fieldValue is String && isEnumLikeFieldName(fieldName)) {
                val enumName = enumTypeNameForField(fieldName, typeName)
                registry.registerEnumValues(enumName, listOf(fieldValue))
            }
        }
    }

    private fun inferFieldType(fieldName: String, fieldValue: Any?, parentInputType: String?): String {
        if (fieldValue is String && isEnumLikeFieldName(fieldName)) {
            return enumTypeNameForField(fieldName, parentInputType)
        }
        return inferSdlType(fieldValue)
    }

    private fun inferListType(value: Any?): String {
        val elements = asList(value)
        if (elements.isEmpty()) return "[String]"
        val merged = elements
            .map { inferSdlType(it) }
            .reduce { left, right -> GraphQLTypeInference.mergeSdlTypes(left, right) }
        return wrapListType(merged)
    }

    private fun inferObjectTypeName(value: Map<*, *>): String {
        if (value.isEmpty()) return "String"
        return "String"
    }

    private fun listElementType(declaredType: String): String? {
        var current = declaredType.trim()
        while (current.endsWith('!')) {
            current = current.dropLast(1)
        }
        if (!current.startsWith('[') || !current.endsWith(']')) return null
        return current.substring(1, current.length - 1).trim().ifBlank { null }
    }

    private fun wrapListType(elementType: String): String {
        val nullableElement = elementType.removeSuffix("!")
        val listType = "[$nullableElement]"
        return if (elementType.endsWith("!")) "$listType!" else listType
    }

    private fun asObjectMap(value: Any?): Map<String, Any?>? {
        return when (value) {
            is Map<*, *> -> value.entries
                .mapNotNull { (key, entryValue) ->
                    (key as? String)?.let { it to entryValue }
                }
                .toMap()
            is JSONObject -> jsonObjectToMap(value)
            else -> null
        }
    }

    private fun asList(value: Any?): List<Any?> {
        return when (value) {
            is List<*> -> value
            is JSONArray -> (0 until value.length()).map { index -> value.opt(index) }
            else -> emptyList()
        }
    }

    private fun jsonObjectToMap(jsonObject: JSONObject): Map<String, Any?> {
        val map = linkedMapOf<String, Any?>()
        for (key in jsonObject.keys()) {
            map[key] = jsonValueToKotlin(jsonObject.get(key))
        }
        return map
    }

    private fun jsonValueToKotlin(value: Any?): Any? {
        return when (value) {
            null, JSONObject.NULL -> null
            is JSONObject -> jsonObjectToMap(value)
            is JSONArray -> (0 until value.length()).map { index -> jsonValueToKotlin(value.opt(index)) }
            else -> value
        }
    }

    private val enumFieldNames = setOf(
        "status", "type", "category", "role", "state", "kind", "mode", "level",
    )

    private fun isEnumLikeFieldName(fieldName: String): Boolean {
        return fieldName.lowercase() in enumFieldNames
    }

    private fun enumTypeNameForField(fieldName: String, parentInputType: String?): String {
        val parentBase = parentInputType
            ?.removeSuffix("Input")
            ?.removeSuffix("Mutation")
            ?: fieldName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        return "${parentBase}${fieldName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }}"
    }
}
