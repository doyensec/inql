package inql.graphql.gqlspection

import com.doyensec.gqlspektion.graphql.GQLSchema
import com.doyensec.gqlspektion.graphql.printer.GQLQueryPrinter
import inql.Config
import inql.Logger
import inql.graphql.GQLSchemaMemoryBackedImpl

class GQLSpektion: IGQLSpection {
    companion object {
        private fun getEnabledPoiCategories(): List<String> {
            val config = Config.getInstance()
            val keys = config.defaults.keys.filter { it.startsWith("report.poi.") }
            return keys.filter { config.getBoolean(it) == true }.map { it.substring("report.poi.".length) }
        }
    }

    override suspend fun parseSchema(jsonSchema: String): GQLSchemaMemoryBackedImpl? {
        val schema: GQLSchema
        try {
            Logger.debug("Parse Schema Called")
            schema = GQLSchema.fromIntrospectionSchema(jsonSchema)
        } catch (e: RuntimeException) {
            Logger.error("Error parsing schema: ${e.message}")
            return null
        }

        // fetch some configs
        val config = Config.getInstance()
        val depth = config.getInt("codegen.depth")!!
        val pad = config.getInt("codegen.pad")!!

        val queries: MutableMap<String, String> = mutableMapOf()
        val mutations: MutableMap<String, String> = mutableMapOf()
        val subscriptions: MutableMap<String, String> = mutableMapOf()

        Logger.info("Parsing queries...")
        for (query in schema.queries) {
            try {
                val printer = GQLQueryPrinter(query.value, GQLQueryPrinter.OperationType.QUERY, maxDepth = depth, padSize = pad)
                queries[query.key] = printer.printSDL()
            } catch (e: RuntimeException) {
                Logger.error("Error parsing query ${query.key}: ${e.message}")
                continue
            }
        }
        Logger.info("Parsed ${queries.size} queries")

        if (schema.schema.isSupportingMutations) {
            Logger.info("Parsing mutations...")
            for (mutation in schema.mutations) {
                try {
                    val printer = GQLQueryPrinter(mutation.value, GQLQueryPrinter.OperationType.MUTATION, maxDepth = depth, padSize = pad)
                    mutations[mutation.key] = printer.printSDL()
                } catch (e: RuntimeException) {
                    Logger.error("Error parsing mutation ${mutation.key}: ${e.message}")
                    continue
                }
            }
            Logger.info("Parsed ${mutations.size} mutations")
        }

        if (schema.schema.isSupportingSubscriptions) {
            Logger.info("Parsing subscriptions...")
            for (subscription in schema.subscriptions) {
                try {
                    val printer = GQLQueryPrinter(subscription.value, GQLQueryPrinter.OperationType.SUBSCRIPTION, maxDepth = depth, padSize = pad)
                    subscriptions[subscription.key] = printer.printSDL()
                } catch (e: RuntimeException) {
                    Logger.error("Error parsing subscription ${subscription.key}: ${e.message}")
                    continue
                }
            }
            Logger.info("Parsed ${subscriptions.size} subscriptions")
        }

        // TODO: parse PoIs
        // TODO: parse Cycles
        return GQLSchemaMemoryBackedImpl(queries, mutations, null, null)
    }

    override suspend fun unload() {
        // Nothing to do
    }
}