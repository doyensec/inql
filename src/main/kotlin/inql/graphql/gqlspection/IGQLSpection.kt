package inql.graphql.gqlspection

import inql.graphql.GQLSchemaMemoryBackedImpl

interface IGQLSpection {
    suspend fun parseSchema(schema: String): GQLSchemaMemoryBackedImpl?
    suspend fun unload()
}