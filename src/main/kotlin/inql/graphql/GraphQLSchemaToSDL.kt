package inql.graphql

import graphql.schema.GraphQLSchema
import graphql.schema.idl.SchemaPrinter

class GraphQLSchemaToSDL {
    companion object {
        fun schemaToSDL(schema: GraphQLSchema): String {
            val printer = SchemaPrinter(
                SchemaPrinter.Options.defaultOptions()
                    .includeScalarTypes(true)
                    .includeSchemaDefinition(true)
                    .includeDirectiveDefinitions(true)
            )
            return printer.print(schema)
        }
    }
}