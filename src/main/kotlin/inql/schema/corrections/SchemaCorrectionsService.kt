package inql.schema.corrections

import graphql.schema.GraphQLSchema
import inql.graphql.GQLSchema
import inql.graphql.GraphQLSchemaToSDL
import inql.history.HistorySchemaCorrections
import inql.Logger

object SchemaCorrectionsService {
    fun apply(schema: GraphQLSchema, corrections: SchemaCorrections): GraphQLSchema? {
        return HistorySchemaCorrections.apply(schema, corrections)
    }

    fun applyToGqlSchema(gqlSchema: GQLSchema, corrections: SchemaCorrections): GQLSchema {
        if (!corrections.hasActiveCorrections()) return gqlSchema

        val baseGql = baseGqlSchema(gqlSchema, corrections)
        val overlay = corrections.copy(sdlOverride = null)
        if (!overlay.hasActiveCorrections()) return baseGql

        val corrected = apply(baseGql.schema, overlay) ?: return baseGql
        return buildGqlSchema(corrected)
    }

    private fun baseGqlSchema(gqlSchema: GQLSchema, corrections: SchemaCorrections): GQLSchema {
        corrections.sdlOverride?.trim()?.takeIf { it.isNotEmpty() }?.let { sdl ->
            return runCatching { GQLSchema(sdl) }.getOrElse { gqlSchema }
        }
        return gqlSchema
    }

    fun buildGqlSchema(schema: GraphQLSchema): GQLSchema {
        return GQLSchema(schema)
    }

    fun mergeInferredWithCorrections(
        base: GraphQLSchema?,
        addition: GraphQLSchema,
        corrections: SchemaCorrections,
    ): GraphQLSchema? {
        return HistorySchemaCorrections.mergeInferredWithCorrections(base, addition, corrections)
    }

    fun shouldBlockInferredType(typeName: String, corrections: SchemaCorrections): Boolean {
        return typeName in corrections.blockedSyntheticTypeNames()
    }

    fun resolveInferredTypeName(typeName: String, corrections: SchemaCorrections): String {
        return corrections.typeAliasMap()[typeName] ?: typeName
    }

    fun validateAndApply(
        schema: GraphQLSchema,
        corrections: SchemaCorrections,
    ): Pair<GraphQLSchema?, List<String>> {
        val (baseSchema, baseErrors) = resolveBaseSchema(schema, corrections)
        if (baseSchema == null) return null to baseErrors

        val overlay = corrections.copy(sdlOverride = null)
        if (!overlay.hasActiveCorrections()) {
            return baseSchema to emptyList()
        }

        val corrected = apply(baseSchema, overlay)
        if (corrected == null) {
            return null to listOf(
                HistorySchemaCorrections.lastApplyError ?: "Failed to apply corrections",
            )
        }
        val sdl = GraphQLSchemaToSDL.schemaToSDL(corrected)
        val validation = SchemaCorrectionValidator.validateSdl(sdl)
        if (!validation.valid) {
            Logger.debug("Schema correction validation failed: ${validation.errors}")
            return null to validation.errors
        }
        return validation.schema to emptyList()
    }

    private fun resolveBaseSchema(
        schema: GraphQLSchema,
        corrections: SchemaCorrections,
    ): Pair<GraphQLSchema?, List<String>> {
        corrections.sdlOverride?.trim()?.takeIf { it.isNotEmpty() }?.let { sdl ->
            val validation = SchemaCorrectionValidator.validateSdl(sdl)
            if (!validation.valid) {
                Logger.debug("SDL override validation failed: ${validation.errors}")
                return null to validation.errors
            }
            return validation.schema to emptyList()
        }
        return schema to emptyList()
    }
}
