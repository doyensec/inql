package inql.history

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLUnionType

/**
 * Imports GraphQL schema types into an [SdlTypeRegistry].
 */
object SchemaMerger {
    private val builtInScalars = setOf("String", "Int", "Float", "Boolean", "ID")

    private fun isUserDefinedType(name: String): Boolean {
        return !name.startsWith("__") && name !in builtInScalars
    }

    internal fun importToRegistry(schema: GraphQLSchema): SdlTypeRegistry {
        val registry = SdlTypeRegistry()
        importIntoRegistry(registry, schema)
        return registry
    }

    internal fun importIntoRegistry(registry: SdlTypeRegistry, schema: GraphQLSchema) {
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
