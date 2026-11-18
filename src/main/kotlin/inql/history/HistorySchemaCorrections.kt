package inql.history

import graphql.schema.GraphQLSchema
import inql.Logger
import inql.schema.corrections.SchemaCorrections

internal object HistorySchemaCorrections {
    var lastApplyError: String? = null
        private set

    fun apply(schema: GraphQLSchema, corrections: SchemaCorrections): GraphQLSchema? {
        lastApplyError = null
        if (!corrections.hasActiveCorrections()) return schema
        val registry = SchemaMerger.importToRegistry(schema)
        registry.setTypeAliases(corrections.typeAliasMap())
        registry.setBlockedTypeNames(corrections.blockedSyntheticTypeNames())
        registry.applyCorrections(corrections)
        val built = registry.toSchema()
        if (built == null) {
            lastApplyError = registry.lastSchemaBuildError
            Logger.debug("Schema rebuild failed after corrections: $lastApplyError")
        }
        return built
    }
}
