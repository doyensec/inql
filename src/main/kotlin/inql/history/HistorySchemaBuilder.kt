package inql.history

import graphql.schema.GraphQLSchema
import inql.graphql.GraphQLOperation
import inql.graphql.Utils
import inql.schema.corrections.SchemaCorrections

object HistorySchemaBuilder {
    /**
     * Incrementally merges [operation] into [registry] without rebuilding the full schema graph.
     * @return true when the registry changed.
     */
    internal fun mergeOperationIntoRegistry(
        registry: SdlTypeRegistry,
        operation: GraphQLOperation,
        responseBody: String?,
        responseStatusCode: Int? = null,
    ): Boolean {
        val document = Utils.normalizeGraphQLDocument(operation.query)
        if (!Utils.isGraphQLDocument(document)) return false

        val errorHints = GraphQLErrorTypeHints.parse(responseBody)
        val responseDataBody = responseBody?.takeIf {
            canUseResponseEvidence(responseStatusCode, it) &&
                ResponseDataParser.extractData(it) != null
        }
        val rejectedFields = if (responseDataBody != null) {
            emptySet()
        } else {
            responseBody?.let { HistoryResponseValidator.getRejectedFieldNames(it) } ?: emptySet()
        }

        return QueryAstToSchema.populateRegistry(
            registry = registry,
            query = document,
            operationType = operation.operationType,
            rejectedFieldNames = rejectedFields,
            responseBody = responseDataBody,
            variables = operation.variables,
            errorHints = errorHints,
        )
    }

    internal fun registryFromSchema(
        schema: GraphQLSchema,
        corrections: SchemaCorrections = SchemaCorrections.EMPTY,
    ): SdlTypeRegistry {
        val registry = SdlTypeRegistry()
        registry.setTypeAliases(corrections.typeAliasMap())
        registry.setBlockedTypeNames(corrections.blockedSyntheticTypeNames())
        SchemaMerger.importIntoRegistry(registry, schema)
        for (blocked in corrections.blockedSyntheticTypeNames()) {
            registry.removeType(blocked)
        }
        if (corrections.hasActiveCorrections()) {
            registry.applyCorrections(corrections)
        }
        return registry
    }

    internal fun finalizeRegistry(
        registry: SdlTypeRegistry,
        corrections: SchemaCorrections = SchemaCorrections.EMPTY,
    ): GraphQLSchema? {
        if (corrections.hasActiveCorrections()) {
            registry.setTypeAliases(corrections.typeAliasMap())
            registry.applyCorrections(corrections)
        }
        return registry.toSchema()
    }

    private fun canUseResponseEvidence(responseStatusCode: Int?, responseBody: String): Boolean {
        if (responseStatusCode == null || responseStatusCode == 200) return true
        return HistoryResponseValidator.hasOnlyApplicationLevelErrors(responseBody)
    }
}
