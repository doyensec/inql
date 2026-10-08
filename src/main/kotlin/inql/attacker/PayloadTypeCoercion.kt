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
    fun coerce(value: JsonElement, declaredType: String?, originalValue: JsonElement?): JsonElement {
        val target = targetType(declaredType, originalValue) ?: return value
        return target.convert(value) ?: value
    }

    private fun targetType(declaredType: String?, originalValue: JsonElement?): PayloadValueType? {
        val type = declaredType?.trim()
        if (type != null && type.startsWith("[")) return null
        when (type?.trimEnd('!')) {
            "Int" -> return PayloadValueType.INT
            "Float" -> return PayloadValueType.FLOAT
            "Boolean" -> return PayloadValueType.BOOLEAN
            "String" -> return PayloadValueType.STRING
            "ID" -> return null // IDs accept both strings and integers.
        }
        if (originalValue == null || !originalValue.isJsonPrimitive) return null
        val original = originalValue.asJsonPrimitive
        return when {
            original.isNumber -> PayloadValueType.FLOAT
            original.isBoolean -> PayloadValueType.BOOLEAN
            original.isString -> PayloadValueType.STRING
            else -> null
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
            else -> value
        }
    }
}
