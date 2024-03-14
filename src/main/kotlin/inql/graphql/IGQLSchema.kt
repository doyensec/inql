package inql.graphql

import com.google.gson.JsonParser
import inql.savestate.BurpSerializable

interface IGQLElement {
    val type: GQLSchemaMemoryBackedImpl.GQLElementType
    val name: String
    val content: String
}

abstract class IGQLSchema {
    abstract suspend fun getQuery(name: String): IGQLElement?
    abstract suspend fun getMutation(name: String): IGQLElement?
    abstract suspend fun listQueries(): List<String>
    abstract suspend fun listMutations(): List<String>
    abstract suspend fun getPointsOfInterestAsJson(): String
    abstract suspend fun getPointsOfInterest(): Map<String, List<IGQLElement>>
    abstract suspend fun getCycleDetectionResultsAsText(): String
}
