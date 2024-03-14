package inql.graphql

import com.google.gson.JsonParser
import inql.Config
import inql.Logger
import inql.session.Session
import inql.graphql.gqlspection.PyGQLSpection
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.withContext

class CacheableSchema(val json: String) {
    val id: Int = nextId.getAndIncrement()

    companion object {
        private val nextId = AtomicInteger(0)
    }
}

class GQLSchemaMemoryBackedImpl private constructor(val session: Session, val schema: CacheableSchema) : IGQLSchema() {
    constructor(session: Session): this(session, CacheableSchema(session.schema.json))

    private val config = Config.getInstance()
    private val gqlspection = PyGQLSpection.getInstance()

    private var cachedQueries: List<String>? = null
    private var cachedMutations: List<String>? = null
    private var cachedPointsOfInterest: String? = null
    private var cachedCycleDetectionResults: String? = null

    private val queryValues: HashMap<String, IGQLElement> = HashMap()
    private val mutationValues: HashMap<String, IGQLElement> = HashMap()

    enum class GQLElementType { QUERY, MUTATION, POI }

    data class GQLElement (
        override val type: GQLElementType,
        override val name: String,
        override val content: String
    ) : IGQLElement

    override suspend fun getQuery(name: String): IGQLElement? = withContext(gqlspection.jythonDispatcher) {
        queryValues[name]?.let { return@withContext it }
        val depth = session.uiSettings.maxQueryDepth
        val pad = session.uiSettings.padding
        val content = gqlspection.getQuery(schema, name, depth, pad) ?: return@withContext null
        GQLElement(GQLElementType.QUERY, name, content).also { queryValues[name] = it }
    }

    override suspend fun getMutation(name: String): IGQLElement? = withContext(gqlspection.jythonDispatcher) {
        mutationValues[name]?.let { return@withContext it }
        val depth = session.uiSettings.maxQueryDepth
        val pad = session.uiSettings.padding
        val content = gqlspection.getMutation(schema, name, depth, pad) ?: return@withContext null
        GQLElement(GQLElementType.MUTATION, name, content).also { mutationValues[name] = it }
    }

    override suspend fun listQueries(): List<String> = withContext(gqlspection.jythonDispatcher) {
        cachedQueries ?: gqlspection.listQueries(schema).also { cachedQueries = it }
    }

    override suspend fun listMutations(): List<String> = withContext(gqlspection.jythonDispatcher) {
        cachedMutations ?: gqlspection.listMutations(schema).also { cachedMutations = it }
    }

    override suspend fun getPointsOfInterestAsJson(): String = withContext(gqlspection.jythonDispatcher) {
        cachedPointsOfInterest ?: gqlspection.getPointsOfInterest(
            schema,
            config.defaults.keys
                .filter { it.startsWith("report.poi.type.") && config.getBoolean(it) }
                .map { it.removePrefix("report.poi.type.") },
            config.getString("report.poi.custom_keywords").split('\n'),
            config.getInt("report.cycles.depth")
        ).also { cachedPointsOfInterest = it }
    }

    override suspend fun getPointsOfInterest(): Map<String, List<IGQLElement>> {
        return getPointsOfInterestAsJson().let { json ->
            JsonParser.parseString(json).asJsonObject.entrySet().associate { (category, findings) ->
                category to findings.asJsonArray.map { finding ->
                    val poi = finding.asJsonObject
                    GQLElement(
                        GQLElementType.POI,
                        poi.get("path").asString,
                        poi.get("description")?.asString ?: ""
                    )
                }
            }
        }
    }

    override suspend fun getCycleDetectionResultsAsText(): String = withContext(gqlspection.jythonDispatcher) {
        cachedCycleDetectionResults ?:
            gqlspection.getCycleDetectionResults(schema, config.getInt("report.cycles.depth"))
                .also { cachedCycleDetectionResults = it }
    }
}
