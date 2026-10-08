package inql.attacker

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import graphql.language.Argument
import graphql.language.ArrayValue
import graphql.language.AstPrinter
import graphql.language.AstTransformer
import graphql.language.BooleanValue
import graphql.language.Document
import graphql.language.EnumValue
import graphql.language.Field
import graphql.language.FloatValue
import graphql.language.IntValue
import graphql.language.Node
import graphql.language.NodeVisitorStub
import graphql.language.NullValue
import graphql.language.ObjectValue
import graphql.language.OperationDefinition
import graphql.language.StringValue
import graphql.language.TypeName
import graphql.language.Value
import graphql.language.VariableDefinition
import graphql.language.VariableReference
import graphql.parser.Parser
import graphql.util.TraversalControl
import graphql.util.TraverserContext
import graphql.util.TreeTransformerUtil

object QueryArgumentPromoter {
    private val parser = Parser()

    fun promote(
        query: String,
        operationName: String?,
        selected: List<BatchVariable>,
        baseVariables: JsonObject,
    ): Pair<String, JsonObject> {
        val toPromote = selected
            .filter { it.kind == BatchVariableKind.ARGUMENT }
            .map { it.graphqlVariable }
            .toSet()
        if (toPromote.isEmpty()) {
            return Pair(query, baseVariables)
        }

        val seeded = baseVariables.deepCopy()
        val types = selected
            .filter { it.kind == BatchVariableKind.ARGUMENT && it.jsonPath.size == 1 }
            .associate { it.graphqlVariable to (it.type ?: "String") }

        val document = parser.parseDocument(query)
        val transformed = AstTransformer().transform(
            document,
            PromoteVisitor(toPromote, seeded),
        ) as Document

        val operation = BatchVariableCollector.selectOperation(
            transformed.definitions.filterIsInstance<OperationDefinition>(),
            operationName,
        ) ?: throw AliasBatchException("Could not find the GraphQL operation after promoting arguments.")

        val defs = operation.variableDefinitions.toMutableList()
        for (name in toPromote) {
            if (defs.none { it.name == name }) {
                defs.add(
                    VariableDefinition.newVariableDefinition()
                        .name(name)
                        .type(TypeName(types[name] ?: "String"))
                        .build(),
                )
            }
        }
        val newOperation = operation.transform { it.variableDefinitions(defs) }
        val newDocument = transformed.transform { builder ->
            builder.definitions(
                transformed.definitions.map { def ->
                    if (def === operation) newOperation else def
                },
            )
        }
        return Pair(AstPrinter.printAst(newDocument), seeded)
    }

    private class PromoteVisitor(
        private val toPromote: Set<String>,
        private val seeded: JsonObject,
    ) : NodeVisitorStub() {
        override fun visitArgument(argument: Argument, data: TraverserContext<Node<*>>): TraversalControl {
            if (argument.value is VariableReference) return TraversalControl.CONTINUE
            val fieldPath = ancestorFields(data)
            if (fieldPath.isEmpty()) return TraversalControl.CONTINUE
            val variableName = BatchVariableCollector.sanitizeName(fieldPath + argument.name)
            if (variableName !in toPromote) return TraversalControl.CONTINUE
            if (!seeded.has(variableName)) {
                seeded.add(variableName, valueToJson(argument.value))
            }
            TreeTransformerUtil.changeNode(
                data,
                argument.transform { it.value(VariableReference.of(variableName)) },
            )
            return TraversalControl.CONTINUE
        }

        private fun ancestorFields(ctx: TraverserContext<Node<*>>): List<String> {
            val names = ArrayList<String>()
            var current: TraverserContext<Node<*>>? = ctx.parentContext
            while (current != null) {
                val node = current.thisNode()
                if (node is Field) names.add(node.name)
                current = current.parentContext
            }
            return names.asReversed()
        }
    }

    private fun valueToJson(value: Value<*>): JsonElement {
        return when (value) {
            is StringValue -> JsonPrimitive(value.value)
            is IntValue -> JsonPrimitive(value.value)
            is FloatValue -> JsonPrimitive(value.value)
            is BooleanValue -> JsonPrimitive(value.isValue)
            is EnumValue -> JsonPrimitive(value.name)
            is NullValue -> JsonNull.INSTANCE
            is ArrayValue -> JsonArray().also { array ->
                value.values.forEach { array.add(valueToJson(it)) }
            }
            is ObjectValue -> JsonObject().also { obj ->
                value.objectFields.forEach { field ->
                    obj.add(field.name, valueToJson(field.value))
                }
            }
            else -> JsonPrimitive(value.toString())
        }
    }
}
