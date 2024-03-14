package inql.graphql

import burp.api.montoya.persistence.PersistedObject
import inql.Logger
import inql.savestate.BurpDeserializableToObject

class GQLSchemaMemoryBackedImpl private constructor(
    queries: List<IGQLElement>,
    mutations: List<IGQLElement>,
    val jsonPointsOfInterest: String?,
    val cycleDetectionResults: String?,
) : IGQLSchema() {

    private val queries: HashMap<String, IGQLElement> = HashMap()
    private val mutations: HashMap<String, IGQLElement> = HashMap()
    private val pointsOfInterest: HashMap<String, List<IGQLElement>> = HashMap()

    init {
        this.queries.putAll(queries.associateBy { it.name() })
        this.mutations.putAll(mutations.associateBy { it.name() })
        if (this.jsonPointsOfInterest != null) {
            this.pointsOfInterest.putAll(parsePointsOfInterestToMap(jsonPointsOfInterest))
        }
    }

    companion object : BurpDeserializableToObject<GQLSchemaMemoryBackedImpl> {
        override fun burpDeserialize(obj: PersistedObject): GQLSchemaMemoryBackedImpl {
            val queriesObj = obj.getChildObject("queries")
            val mutationsObj = obj.getChildObject("mutations")
            val jsonPointsOfInterest = obj.getString("jsonPOI")
            val cycleDetectionResults = obj.getString("cycleDetectionResults")

            val queriesKeys = queriesObj.childObjectKeys()
            val mutationsKeys = mutationsObj.childObjectKeys()
            val queries = ArrayList<IGQLElement>(queriesKeys.size)
            val mutations = ArrayList<IGQLElement>(mutationsKeys.size)

            Logger.debug("Loading ${queriesKeys.size} queries")
            for (name in queriesKeys) {
                val qObj = queriesObj.getChildObject(name)
                queries.add(
                    GQLElement(
                        GQLElementType.QUERY,
                        qObj.getString("name"),
                        qObj.getString("content"),
                    ),
                )
            }

            Logger.debug("Loading ${mutationsKeys.size} mutations")
            for (name in mutationsKeys) {
                val mObj = mutationsObj.getChildObject(name)
                mutations.add(
                    GQLElement(
                        GQLElementType.MUTATION,
                        mObj.getString("name"),
                        mObj.getString("content"),
                    ),
                )
            }

            return GQLSchemaMemoryBackedImpl(
                queries,
                mutations,
                jsonPointsOfInterest,
                cycleDetectionResults,
            )
        }
    }

    constructor(queries: Map<String, String>, mutations: Map<String, String>, jsonPointsOfInterest: String?, cycleDetectionResults: String?) : this(
        queries.map { GQLElement(GQLElementType.QUERY, it.key, it.value) },
        mutations.map { GQLElement(GQLElementType.MUTATION, it.key, it.value) },
        jsonPointsOfInterest,
        cycleDetectionResults,
    )

    class GQLElement(val _type: GQLElementType, val _name: String, val _content: String) : IGQLElement {
        override fun type(): GQLElementType {
            return _type
        }

        override fun name(): String {
            return _name
        }

        override fun content(): String {
            return _content
        }

        override fun burpSerialize(): PersistedObject {
            val obj = PersistedObject.persistedObject()
            obj.setInteger("type", type().ordinal)
            obj.setString("name", name())
            obj.setString("content", content())
            return obj
        }

        override fun toString(): String {
            return this._name
        }
    }

    override fun getQueries(): Map<String, IGQLElement> {
        return this.queries
    }

    override fun getMutations(): Map<String, IGQLElement> {
        return this.mutations
    }

    override fun getPointsOfInterest(): Map<String, List<IGQLElement>> {
        return this.pointsOfInterest
    }

    override fun getPointsOfInterestAsJson(): String? {
        return this.jsonPointsOfInterest
    }

    override fun getCycleDetectionResultsAsText(): String? {
        return this.cycleDetectionResults
    }

    override fun burpSerialize(): PersistedObject {
        val mainObj = PersistedObject.persistedObject()
        val queriesObj = PersistedObject.persistedObject()
        val mutationsObj = PersistedObject.persistedObject()

        Logger.debug("Saving ${queries.size} queries")
        for (query in queries) {
            queriesObj.setChildObject(query.key, query.value.burpSerialize())
        }

        Logger.debug("Saving ${mutations.size} mutations")
        for (mutation in mutations) {
            mutationsObj.setChildObject(mutation.key, mutation.value.burpSerialize())
        }

        mainObj.setChildObject("queries", queriesObj)
        mainObj.setChildObject("mutations", mutationsObj)
        if (this.jsonPointsOfInterest != null) {
            mainObj.setString("jsonPOI", jsonPointsOfInterest)
        }
        if (this.cycleDetectionResults != null) {
            mainObj.setString("cycleDetectionResults", cycleDetectionResults)
        }
        return mainObj
    }
}
