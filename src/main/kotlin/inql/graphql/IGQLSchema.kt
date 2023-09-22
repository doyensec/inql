package inql.graphql

import com.google.gson.JsonParser
import inql.savestate.BurpSerializable

abstract class IGQLSchema : BurpSerializable {
    companion object {
        fun parsePointsOfInterestToMap(poi_json: String): Map<String, List<GQLSchemaMemoryBackedImpl.GQLElement>> {
            val categories = JsonParser.parseString(poi_json).asJsonObject.asMap()
            val result = HashMap<String, ArrayList<GQLSchemaMemoryBackedImpl.GQLElement>>(categories.size)

            for ((cat, finding) in categories) {
                val items = finding.asJsonArray
                val catList = ArrayList<GQLSchemaMemoryBackedImpl.GQLElement>(items.size())
                for (item in items) {
                    val poi = item.asJsonObject
                    val gqlPoi = GQLSchemaMemoryBackedImpl.GQLElement(
                        GQLElementType.POI,
                        poi.get("path").asString,
                        if (poi.has("description")) poi.get("description").asString else "",
                    )
                    catList.add(gqlPoi)
                }
                result[cat] = catList
            }
            return result
        }
    }

    enum class GQLElementType {
        QUERY,
        MUTATION,
        POI,
    }

    interface IGQLElement : BurpSerializable {
        fun type(): GQLElementType
        fun name(): String
        fun content(): String
    }

    abstract fun getQueries(): Map<String, IGQLElement>
    abstract fun getMutations(): Map<String, IGQLElement>
    abstract fun getPointsOfInterest(): Map<String, List<IGQLElement>>
    abstract fun getPointsOfInterestAsJson(): String?

    fun getPointsOfInterestAsText(): String {
        val sb = StringBuilder()
        for ((cat, findings) in this.getPointsOfInterest()) {
            sb.appendLine("Category: $cat")
            sb.appendLine()
            for (poi in findings) {
                sb.appendLine(poi.toString())
            }
            sb.appendLine()
        }
        return sb.toString()
    }
}
