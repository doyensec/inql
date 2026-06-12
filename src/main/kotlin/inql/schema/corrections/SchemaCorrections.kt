package inql.schema.corrections

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject

/**
 * User-defined fixes applied on top of inferred/reconstructed schemas.
 */
data class SchemaCorrections(
    val typeRenames: Map<String, String> = emptyMap(),
    val typeMerges: Map<String, String> = emptyMap(),
    val removedTypes: Set<String> = emptySet(),
    val removedFields: Map<String, Set<String>> = emptyMap(),
    val fieldTypeOverrides: Map<String, Map<String, String>> = emptyMap(),
    val argumentTypeOverrides: Map<String, Map<String, Map<String, String>>> = emptyMap(),
    /** input type → field name → allowed enum values (from server error hints). */
    val inputEnumFieldOverrides: Map<String, Map<String, List<String>>> = emptyMap(),
    /** leaf input type → field name → full display path (root.nested.field) for the corrections UI. */
    val inputEnumFieldDisplayPaths: Map<String, Map<String, String>> = emptyMap(),
    /** enum type name → allowed values (from server error hints). */
    val enumValueOverrides: Map<String, List<String>> = emptyMap(),
    /** Full SDL replacement from the corrections editor; does not mutate the inferred base schema. */
    val sdlOverride: String? = null,
    val removeAllPlaceholders: Boolean = false,
) {
    companion object {
        val EMPTY = SchemaCorrections()
        private val gson = Gson()
        private val exportGson = GsonBuilder().setPrettyPrinting().create()

        fun fromJson(json: String?): SchemaCorrections {
            if (json.isNullOrBlank()) return EMPTY
            return runCatching {
                val root = gson.fromJson(json, JsonObject::class.java) ?: return EMPTY
                val parsed = gson.fromJson(json, SchemaCorrections::class.java) ?: EMPTY
                parsed.copy(inputEnumFieldOverrides = parseInputEnumFieldOverrides(root))
            }.getOrElse { EMPTY }
        }

        private fun parseInputEnumFieldOverrides(root: JsonObject): Map<String, Map<String, List<String>>> {
            val section = root.get("inputEnumFieldOverrides") ?: return emptyMap()
            if (!section.isJsonObject) return emptyMap()
            val result = linkedMapOf<String, Map<String, List<String>>>()
            for ((inputType, fieldsEl) in section.asJsonObject.entrySet()) {
                if (!fieldsEl.isJsonObject) continue
                val fieldMap = linkedMapOf<String, List<String>>()
                for ((fieldName, valuesEl) in fieldsEl.asJsonObject.entrySet()) {
                    if (!valuesEl.isJsonArray) continue
                    val values = valuesEl.asJsonArray.mapNotNull { element ->
                        if (element.isJsonPrimitive) element.asString else null
                    }
                    if (values.isNotEmpty()) {
                        fieldMap[fieldName] = values
                    }
                }
                if (fieldMap.isNotEmpty()) {
                    result[inputType] = fieldMap
                }
            }
            return result
        }

    }

    fun isEmpty(): Boolean {
        return this == EMPTY ||
            typeRenames.isEmpty() &&
            typeMerges.isEmpty() &&
            removedTypes.isEmpty() &&
            removedFields.values.all { it.isEmpty() } &&
            fieldTypeOverrides.isEmpty() &&
            argumentTypeOverrides.isEmpty() &&
            inputEnumFieldOverrides.isEmpty() &&
            inputEnumFieldDisplayPaths.isEmpty() &&
            enumValueOverrides.isEmpty() &&
            sdlOverride.isNullOrBlank() &&
            !removeAllPlaceholders
    }

    fun hasActiveCorrections(): Boolean = !isEmpty()

    fun toJson(): String = exportGson.toJson(toJsonObject())

    private fun toJsonObject(): JsonObject {
        val root = JsonObject()
        if (typeRenames.isNotEmpty()) {
            root.add("typeRenames", gson.toJsonTree(typeRenames))
        }
        if (typeMerges.isNotEmpty()) {
            root.add("typeMerges", gson.toJsonTree(typeMerges))
        }
        if (removedTypes.isNotEmpty()) {
            root.add("removedTypes", gson.toJsonTree(removedTypes))
        }
        val activeRemovedFields = removedFields.filterValues { it.isNotEmpty() }
        if (activeRemovedFields.isNotEmpty()) {
            root.add("removedFields", gson.toJsonTree(activeRemovedFields))
        }
        if (fieldTypeOverrides.isNotEmpty()) {
            root.add("fieldTypeOverrides", gson.toJsonTree(fieldTypeOverrides))
        }
        if (argumentTypeOverrides.isNotEmpty()) {
            root.add("argumentTypeOverrides", gson.toJsonTree(argumentTypeOverrides))
        }
        if (inputEnumFieldOverrides.isNotEmpty()) {
            root.add("inputEnumFieldOverrides", gson.toJsonTree(inputEnumFieldOverrides))
        }
        if (inputEnumFieldDisplayPaths.isNotEmpty()) {
            root.add("inputEnumFieldDisplayPaths", gson.toJsonTree(inputEnumFieldDisplayPaths))
        }
        if (enumValueOverrides.isNotEmpty()) {
            root.add("enumValueOverrides", gson.toJsonTree(enumValueOverrides))
        }
        if (!sdlOverride.isNullOrBlank()) {
            root.addProperty("sdlOverride", sdlOverride)
        }
        if (removeAllPlaceholders) {
            root.addProperty("removeAllPlaceholders", true)
        }
        return root
    }

    fun withRename(oldName: String, newName: String): SchemaCorrections {
        if (oldName == newName) return this
        return copy(typeRenames = typeRenames + (oldName to newName))
    }

    /**
     * Applies a rename from a GraphQL error suggestion. When [wrongType] is already the target of
     * an existing rename (e.g. manual `RankedCveEntry → Active_banasd`, error says `Active_banasd → X`),
     * updates the original rule to `RankedCveEntry → X` instead of adding a chained second rule.
     */
    fun withSuggestionRename(wrongType: String, suggestedType: String): SchemaCorrections {
        if (wrongType == suggestedType) return this
        val parentSource = typeRenames.entries.find { it.value == wrongType }?.key
        return if (parentSource != null) {
            copy(typeRenames = typeRenames - parentSource - wrongType + (parentSource to suggestedType))
        } else {
            withRename(wrongType, suggestedType)
        }
    }

    fun withSdlOverride(sdl: String): SchemaCorrections {
        val trimmed = sdl.trim()
        if (trimmed.isEmpty()) return copy(sdlOverride = null)
        return copy(sdlOverride = trimmed)
    }

    fun withInputEnumFieldOverride(
        inputTypeName: String,
        fieldName: String,
        allowedValues: List<String>,
        displayPath: String? = null,
    ): SchemaCorrections {
        if (allowedValues.isEmpty()) return this
        val inputOverrides = inputEnumFieldOverrides[inputTypeName].orEmpty()
        var updated = copy(
            inputEnumFieldOverrides = inputEnumFieldOverrides + mapOf(
                inputTypeName to (inputOverrides + (fieldName to allowedValues)),
            ),
        )
        val path = displayPath?.trim()?.takeIf { it.isNotEmpty() }
        if (path != null) {
            val pathOverrides = updated.inputEnumFieldDisplayPaths[inputTypeName].orEmpty()
            updated = updated.copy(
                inputEnumFieldDisplayPaths = updated.inputEnumFieldDisplayPaths + mapOf(
                    inputTypeName to (pathOverrides + (fieldName to path)),
                ),
            )
        }
        return updated
    }

    fun withEnumValueOverride(enumTypeName: String, allowedValues: List<String>): SchemaCorrections {
        if (allowedValues.isEmpty()) return this
        return copy(enumValueOverrides = enumValueOverrides + (enumTypeName to allowedValues))
    }

    fun withoutEnumValueOverride(enumTypeName: String): SchemaCorrections {
        return copy(enumValueOverrides = enumValueOverrides - enumTypeName)
    }

    fun withoutInputEnumFieldOverride(inputTypeName: String, fieldName: String): SchemaCorrections {
        val inputOverrides = inputEnumFieldOverrides[inputTypeName] ?: return this
        val updated = inputOverrides - fieldName
        val topLevel = if (updated.isEmpty()) {
            inputEnumFieldOverrides - inputTypeName
        } else {
            inputEnumFieldOverrides + (inputTypeName to updated)
        }
        val pathOverrides = inputEnumFieldDisplayPaths[inputTypeName].orEmpty() - fieldName
        val topLevelPaths = if (pathOverrides.isEmpty()) {
            inputEnumFieldDisplayPaths - inputTypeName
        } else {
            inputEnumFieldDisplayPaths + (inputTypeName to pathOverrides)
        }
        return copy(inputEnumFieldOverrides = topLevel, inputEnumFieldDisplayPaths = topLevelPaths)
    }

    fun withArgumentTypeOverride(
        parentType: String,
        fieldName: String,
        argumentName: String,
        type: String,
    ): SchemaCorrections {
        val parentOverrides = argumentTypeOverrides[parentType].orEmpty()
        val fieldOverrides = parentOverrides[fieldName].orEmpty()
        return copy(
            argumentTypeOverrides = argumentTypeOverrides + mapOf(
                parentType to (parentOverrides + mapOf(fieldName to (fieldOverrides + (argumentName to type)))),
            ),
        )
    }

    fun withoutArgumentTypeOverride(
        parentType: String,
        fieldName: String,
        argumentName: String,
    ): SchemaCorrections {
        val parentOverrides = argumentTypeOverrides[parentType] ?: return this
        val fieldOverrides = parentOverrides[fieldName] ?: return this
        val updatedFieldOverrides = fieldOverrides - argumentName
        val updatedParentOverrides = if (updatedFieldOverrides.isEmpty()) {
            parentOverrides - fieldName
        } else {
            parentOverrides + (fieldName to updatedFieldOverrides)
        }
        val topLevel = if (updatedParentOverrides.isEmpty()) {
            argumentTypeOverrides - parentType
        } else {
            argumentTypeOverrides + (parentType to updatedParentOverrides)
        }
        return copy(argumentTypeOverrides = topLevel)
    }

    fun typeAliasMap(): Map<String, String> {
        val aliases = linkedMapOf<String, String>()
        for ((wrong, right) in typeMerges) {
            aliases[wrong] = right
        }
        for ((wrong, right) in typeRenames) {
            aliases[wrong] = right
        }
        return aliases.mapValues { (source, _) -> resolveAliasChain(source, aliases) }
    }

    private fun resolveAliasChain(source: String, aliases: Map<String, String>): String {
        var current = source
        val visited = mutableSetOf<String>()
        while (current in aliases && current !in visited) {
            visited.add(current)
            current = aliases[current]!!
        }
        return current
    }

    fun blockedSyntheticTypeNames(): Set<String> = typeRenames.keys + typeMerges.keys
}
