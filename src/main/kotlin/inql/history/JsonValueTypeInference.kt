package inql.history

import org.json.JSONArray
import org.json.JSONObject

/**
 * Infers GraphQL SDL types from JSON variable values and response payloads.
 */
internal object JsonValueTypeInference {
    fun inferSdlType(value: Any?): String? {
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
            is String -> GraphQLTypeInference.inferScalarFromStringValue(value)
            is Map<*, *>, is JSONObject -> null
            is List<*>, is JSONArray -> inferListType(value)
            else -> null
        }
    }

    fun extractInputFields(
        value: Any?,
        parentInputType: String,
        registry: SdlTypeRegistry? = null,
    ): Map<String, String> {
        val objectValue = asObjectMap(value) ?: return emptyMap()
        val fields = linkedMapOf<String, String>()
        for ((fieldName, fieldValue) in objectValue) {
            val nestedObject = asObjectMap(fieldValue)
            if (nestedObject != null) {
                val nestedTypeName = GraphQLTypeInference.syntheticNestedInputFieldType(parentInputType, fieldName)
                val nestedFields = extractInputFields(fieldValue, nestedTypeName, registry)
                if (nestedFields.isNotEmpty()) {
                    registry?.registerInputFields(nestedTypeName, nestedFields)
                    fields[fieldName] = GraphQLTypeInference.mergeSdlTypes(
                        fields[fieldName],
                        GraphQLTypeInference.ensureNonNullSdlType(nestedTypeName),
                    )
                }
            } else {
                inferSdlType(fieldValue)?.let { fieldType ->
                    fields[fieldName] = GraphQLTypeInference.mergeSdlTypes(fields[fieldName], fieldType)
                }
            }
        }
        return fields
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
        if (GraphQLTypeInference.isKnownCustomScalar(baseType)) {
            registry.ensureArgumentTypeStub(baseType)
            return
        }
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
            is String -> registry.registerEnumValues(baseType, listOf(value))
            else -> registerObjectFields(registry, baseType, value)
        }
    }

    private fun registerObjectFields(registry: SdlTypeRegistry, typeName: String, value: Any?) {
        val fields = extractInputFields(value, typeName, registry)
        if (fields.isNotEmpty()) {
            registry.registerInputFields(typeName, fields)
        }
    }

    private fun inferListType(value: Any?): String? {
        val elements = asList(value)
        if (elements.isEmpty()) return null
        val merged = elements
            .mapNotNull { inferSdlType(it) }
            .reduceOrNull { left, right -> GraphQLTypeInference.mergeSdlTypes(left, right) }
            ?: return null
        return wrapListType(merged)
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
}
