package inql.graphql

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLList
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLNonNull
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType

object GraphQLTypeSDL {
    fun formatType(schema: GraphQLSchema, typeName: String): String {
        val type = schema.getType(typeName) as? GraphQLNamedType
            ?: return "# Type not found: $typeName"
        return formatType(type)
    }

    fun formatType(type: GraphQLNamedType): String {
        return when (type) {
            is GraphQLObjectType -> formatObjectType(type)
            is GraphQLInputObjectType -> formatInputObjectType(type)
            is GraphQLEnumType -> formatEnumType(type)
            is GraphQLUnionType -> formatUnionType(type)
            is GraphQLScalarType -> "scalar ${type.name}"
            else -> "# ${type.name}"
        }
    }

    private fun formatObjectType(type: GraphQLObjectType): String {
        return buildString {
            appendLine("type ${type.name} {")
            for (field in type.fieldDefinitions.sortedBy { it.name }) {
                append("  ")
                append(field.name)
                append(formatArguments(field.arguments))
                appendLine(": ${formatGraphQLType(field.type)}")
            }
            append("}")
        }
    }

    private fun formatInputObjectType(type: GraphQLInputObjectType): String {
        return buildString {
            appendLine("input ${type.name} {")
            for (field in type.fieldDefinitions.sortedBy { it.name }) {
                if (field.name == "_inql_placeholder" || field.name == "PLACEHOLDER") continue
                appendLine("  ${field.name}: ${formatGraphQLType(field.type)}")
            }
            append("}")
        }
    }

    private fun formatEnumType(type: GraphQLEnumType): String {
        return buildString {
            appendLine("enum ${type.name} {")
            for (value in type.values) {
                if (value.name == "PLACEHOLDER" || value.name == "_inql_placeholder") continue
                appendLine("  ${value.name}")
            }
            append("}")
        }
    }

    private fun formatUnionType(type: GraphQLUnionType): String {
        val members = type.types.mapNotNull { (it as? GraphQLNamedType)?.name }.sorted()
        return "union ${type.name} = ${members.joinToString(" | ")}"
    }

    private fun formatArguments(arguments: List<graphql.schema.GraphQLArgument>): String {
        if (arguments.isEmpty()) return ""
        val rendered = arguments.sortedBy { it.name }.joinToString(", ") { arg ->
            "${arg.name}: ${formatGraphQLType(arg.type)}"
        }
        return "($rendered)"
    }

    private fun formatGraphQLType(type: GraphQLType): String {
        return when (type) {
            is GraphQLNonNull -> "${formatGraphQLType(type.wrappedType)}!"
            is GraphQLList -> "[${formatGraphQLType(type.wrappedType)}]"
            is GraphQLNamedType -> type.name
            else -> type.toString()
        }
    }
}
