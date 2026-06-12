package inql.history

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLUnionType

/**
 * Merges two partial GraphQL schemas by combining their SDL type definitions.
 */
object SchemaMerger {
    private val builtInScalars = setOf("String", "Int", "Float", "Boolean", "ID")

    private fun isUserDefinedType(name: String): Boolean {
        return !name.startsWith("__") && name !in builtInScalars
    }

    fun merge(base: GraphQLSchema?, addition: GraphQLSchema): GraphQLSchema? {
        val registry = SdlTypeRegistry()
        if (base != null) {
            importIntoRegistry(registry, base)
        }
        importIntoRegistry(registry, addition)
        return registry.toSchema()
    }

    internal fun importToRegistry(schema: GraphQLSchema): SdlTypeRegistry {
        val registry = SdlTypeRegistry()
        importIntoRegistry(registry, schema)
        return registry
    }

    internal fun importIntoRegistry(registry: SdlTypeRegistry, schema: GraphQLSchema) {
        importSchema(registry, schema)
    }

    private fun importSchema(registry: SdlTypeRegistry, schema: GraphQLSchema) {
        for ((name, type) in schema.typeMap) {
            if (!isUserDefinedType(name)) continue
            when (type) {
                is GraphQLObjectType -> registry.importObjectType(type)
                is GraphQLInputObjectType -> registry.importInputObjectType(type)
                is GraphQLUnionType -> registry.importUnionType(type)
                is GraphQLEnumType -> registry.importEnumType(type)
            }
        }
    }
}
