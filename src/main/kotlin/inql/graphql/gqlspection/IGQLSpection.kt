package inql.graphql.gqlspection

import inql.graphql.GQLSchemaMemoryBackedImpl

interface IGQLSpection {
    suspend fun unload()
    suspend fun setLogLevel(level: String)
}
