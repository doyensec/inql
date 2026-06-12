package inql.history

import org.json.JSONArray
import org.json.JSONObject

/**
 * Infers GraphQL SDL types from JSON variable values and response payloads.
 */
internal object JsonValueTypeInference {
    fun inferSdlType(value: Any?): String? {
        return when (value) {
            is Map<*, *>, is JSONObject -> null
            else -> GraphQLTypeInference.inferScalarFromJson(value)
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

    private fun listElementType(declaredType: String): String? {
        var current = declaredType.trim()
        while (current.endsWith('!')) {
            current = current.dropLast(1)
        }
        if (!current.startsWith('[') || !current.endsWith(']')) return null
        return current.substring(1, current.length - 1).trim().ifBlank { null }
    }

    private fun asObjectMap(value: Any?): Map<String, Any?>? {
        return when (value) {
            is Map<*, *> -> value.entries
                .mapNotNull { (key, entryValue) ->
                    (key as? String)?.let { it to entryValue }
                }
                .toMap()
            is JSONObject -> JsonKotlinBridge.jsonObjectToMap(value)
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
}
