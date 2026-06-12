package inql.scanner.scanresults

import inql.graphql.GQLSchema
import inql.graphql.GraphQLTypeSDL

class GQLTypeElement(
    typeName: String,
    private val schemaSupplier: () -> GQLSchema,
) : ScanResultElement(typeName) {
    override fun content(): String = GraphQLTypeSDL.formatType(schemaSupplier().schema, name)
}
