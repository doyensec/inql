package inql.attacker

import com.google.gson.JsonElement
import graphql.language.ArrayValue
import graphql.language.BooleanValue
import graphql.language.Document
import graphql.language.EnumValue
import graphql.language.Field
import graphql.language.FloatValue
import graphql.language.IntValue
import graphql.language.NullValue
import graphql.language.ObjectField
import graphql.language.ObjectValue
import graphql.language.OperationDefinition
import graphql.language.SelectionSet
import graphql.language.StringValue
import graphql.language.Value

/**
 * Writes payloads into literal root field arguments.
 *
 * Payloads are inlined as literals rather than moved into variables: a variable must be declared with the
 * argument's exact schema type (e.g. `ID!` or an input object), which cannot be known without the schema.
 */
object ArgumentInliner {
    private val enumName = Regex("[_A-Za-z][_0-9A-Za-z]*")

    /**
     * Returns [selectionSet] with each payload written at its argument path: the root field's response key,
     * the argument name, then object fields and `[index]` segments. Paths that no longer match the query
     * are ignored.
     */
    fun inline(selectionSet: SelectionSet, overrides: Map<List<String>, JsonElement>): SelectionSet {
        if (overrides.isEmpty()) return selectionSet
        val byField = overrides.entries.groupBy { it.key.first() }
        val selections = selectionSet.selections.map { selection ->
            if (selection !is Field) return@map selection
            val fieldOverrides = byField[BatchVariableCollector.responseKey(selection)] ?: return@map selection
            val arguments = selection.arguments.map { argument ->
                val value = fieldOverrides
                    .filter { it.key[1] == argument.name }
                    .fold(argument.value) { current, (path, payload) -> withValueAt(current, path.drop(2), payload) }
                if (value === argument.value) argument else argument.transform { it.value(value) }
            }
            selection.transform { it.arguments(arguments) }
        }
        return selectionSet.transform { it.selections(selections) }
    }

    /** Applies [inline] to the selected operation of [document]. */
    fun inline(document: Document, operationName: String?, overrides: Map<List<String>, JsonElement>): Document {
        if (overrides.isEmpty()) return document
        val operation = BatchVariableCollector.selectOperation(
            document.definitions.filterIsInstance<OperationDefinition>(),
            operationName,
        ) ?: return document
        val newOperation = operation.transform { it.selectionSet(inline(operation.selectionSet, overrides)) }
        return document.transform { builder ->
            builder.definitions(document.definitions.map { if (it === operation) newOperation else it })
        }
    }

    private fun withValueAt(value: Value<*>, path: List<String>, payload: JsonElement): Value<*> {
        if (path.isEmpty()) return toLiteral(payload, value)
        val rest = path.drop(1)
        val index = BatchVariableCollector.arrayIndex(path.first())
        return when {
            index != null && value is ArrayValue && index < value.values.size -> {
                val values = value.values.toMutableList()
                values[index] = withValueAt(values[index], rest, payload)
                value.transform { it.values(values) }
            }
            index == null && value is ObjectValue -> {
                val fields = value.objectFields.map { field ->
                    if (field.name != path.first()) return@map field
                    field.transform { it.value(withValueAt(field.value, rest, payload)) }
                }
                value.transform { it.objectFields(fields) }
            }
            else -> value
        }
    }

    /** Converts [payload] to a literal; strings replacing an enum literal stay enums when they are valid names. */
    private fun toLiteral(payload: JsonElement, original: Value<*>?): Value<*> {
        return when {
            payload.isJsonNull -> NullValue.newNullValue().build()
            payload.isJsonArray -> ArrayValue.newArrayValue()
                .values(payload.asJsonArray.map { toLiteral(it, null) })
                .build()
            payload.isJsonObject -> ObjectValue.newObjectValue()
                .objectFields(payload.asJsonObject.entrySet().map { (name, value) -> ObjectField(name, toLiteral(value, null)) })
                .build()
            else -> {
                val primitive = payload.asJsonPrimitive
                val text = primitive.asString
                when {
                    primitive.isBoolean -> BooleanValue.of(primitive.asBoolean)
                    primitive.isNumber -> text.toBigIntegerOrNull()?.let { IntValue(it) } ?: FloatValue(text.toBigDecimal())
                    original is EnumValue && isEnumName(text) -> EnumValue.of(text)
                    else -> StringValue.of(text)
                }
            }
        }
    }

    private fun isEnumName(text: String): Boolean {
        return enumName.matches(text) && text != "true" && text != "false" && text != "null"
    }
}
