package inql.scanner.scanresults

import inql.graphql.GQLSchema

class GQLQueryElement(
    name: String,
    val type: GQLSchema.OperationType,
    private val schemaSupplier: () -> GQLSchema,
    private val maxDepth: Int? = null,
) : ScanResultElement(name) {
    override fun content(): String {
        return schemaSupplier().getOperationAsText(name, type, skipCache = true, maxDepth = maxDepth)
    }
}