package inql.attacker

import com.google.gson.JsonElement
import com.google.gson.JsonPrimitive

/**
 * Converts payload values to the JSON type expected by the target variable, so that e.g. wordlist
 * entries sent to an `Int` variable go out as numbers instead of strings (which GraphQL rejects).
 *
 * The declared GraphQL type wins when it is a built-in scalar; otherwise the JSON type of the
 * original value in the request is used as a hint. Values that cannot be converted are sent as-is.
 */
object PayloadTypeCoercion {
    private enum class Kind { NUMBER, INTEGER, BOOLEAN, STRING, UNKNOWN }

    fun coerce(value: JsonElement, declaredType: String?, originalValue: JsonElement?): JsonElement {
        if (!value.isJsonPrimitive) return value
        val primitive = value.asJsonPrimitive
        val text = primitive.asString
        return when (targetKind(declaredType, originalValue)) {
            Kind.INTEGER -> text.toBigIntegerOrNull()?.let { JsonPrimitive(it) } ?: value
            Kind.NUMBER -> text.toBigDecimalOrNull()?.let { JsonPrimitive(it) } ?: value
            Kind.BOOLEAN -> when (text) {
                "true" -> JsonPrimitive(true)
                "false" -> JsonPrimitive(false)
                else -> value
            }
            Kind.STRING -> if (primitive.isString) value else JsonPrimitive(text)
            Kind.UNKNOWN -> value
        }
    }

    private fun targetKind(declaredType: String?, originalValue: JsonElement?): Kind {
        val type = declaredType?.trim()
        if (type != null && type.startsWith("[")) return Kind.UNKNOWN
        when (type?.trimEnd('!')) {
            "Int" -> return Kind.INTEGER
            "Float" -> return Kind.NUMBER
            "Boolean" -> return Kind.BOOLEAN
            "String" -> return Kind.STRING
            "ID" -> return Kind.UNKNOWN // IDs accept both strings and integers.
        }
        if (originalValue == null || !originalValue.isJsonPrimitive) return Kind.UNKNOWN
        val original = originalValue.asJsonPrimitive
        return when {
            original.isNumber -> Kind.NUMBER
            original.isBoolean -> Kind.BOOLEAN
            original.isString -> Kind.STRING
            else -> Kind.UNKNOWN
        }
    }
}

/** JSON type that payloads of a payload set are sent as. */
enum class PayloadValueType(val label: String) {
    /** Follow the variable's declared type, or the type of its original value. */
    AUTO("Auto"),
    STRING("String"),
    INT("Int"),
    FLOAT("Float"),
    BOOLEAN("Boolean"),
    ;

    /** Converts [value] to this type, or returns null if it is not a valid value of this type. */
    fun convert(value: JsonElement): JsonElement? {
        if (this == AUTO || value.isJsonNull) return value
        if (!value.isJsonPrimitive) return null
        val text = value.asString.trim()
        return when (this) {
            STRING -> JsonPrimitive(value.asString)
            INT -> text.toBigIntegerOrNull()?.let { JsonPrimitive(it) }
            FLOAT -> text.toBigDecimalOrNull()?.let { JsonPrimitive(it) }
            BOOLEAN -> text.lowercase().toBooleanStrictOrNull()?.let { JsonPrimitive(it) }
            AUTO -> value
        }
    }

    companion object {
        fun fromIndex(index: Int): PayloadValueType = entries.getOrElse(index) { AUTO }
    }
}
