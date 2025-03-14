package inql.scanner.scanresults

import inql.graphql.GQLSchema

class GQLQueryElement(name: String, val type: GQLSchema.OperationType, val schema: GQLSchema): ScanResultElement(name) {
    public override fun content(): String {
        return schema.getOperationAsText(name, type)
    }
}