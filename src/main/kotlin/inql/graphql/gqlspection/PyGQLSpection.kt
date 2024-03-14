package inql.graphql.gqlspection

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import inql.Config
import inql.Logger
import inql.graphql.GQLSchemaMemoryBackedImpl
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.python.util.PythonInterpreter

class PyGQLSpection private constructor() : IGQLSpection {
    companion object {
        private var instance: PyGQLSpection? = null
        fun getInstance(): PyGQLSpection {
            if (instance == null) instance = PyGQLSpection()
            return instance as PyGQLSpection
        }

        private fun getEnabledPoiCategories(): List<String> {
            val config = Config.getInstance()
            val keys = config.defaults.keys.filter { it.startsWith("report.poi.") }
            return keys.filter { config.getBoolean(it) == true }.map { it.substring("report.poi.".length) }
        }
    }

    private val interpreter = PythonInterpreter()
    private val lock = Mutex()

    init {
        interpreter.exec("import sys; reload(sys); sys.setdefaultencoding('UTF8')")
        interpreter.setOut(System.out)
        interpreter.setErr(System.err)
        interpreter.exec("from gqlspection import log as gql_log")
        interpreter.exec("from gqlspection import GQLSchema")
        interpreter.exec("import logging")
        interpreter.exec("import re")
        interpreter.exec("import json")
    }

    private fun _unload() {
        interpreter.cleanup()
        interpreter.close()
        instance = null
    }

    private fun _parseSchema(schema: String): GQLSchemaMemoryBackedImpl? {
        // Parse schema

        val gson = Gson()
        Logger.debug("Parse Schema Called")
        // Deserialize JSON here to check for errors
        try {
            gson.fromJson(schema, Map::class.java)
            Logger.debug("JSON parsed successfully in Kotlin")
        } catch (e: Exception) {
            Logger.info("Could not parse introspection response")
            Logger.info("Exception: $e")
            throw e
        }

        // fetch some configs
        val config = Config.getInstance()
        val depth = config.getInt("codegen.depth")
        val pad = config.getInt("codegen.pad")

        try {
            // define name validation function
            Logger.debug("Passing data to Python")
            interpreter.exec("name_regex = re.compile('^[_A-Za-z][_0-9A-Za-z]*\$')")
            interpreter.exec(
                "def is_valid_graphql_name(name):\n" +
                    "    return name_regex.match(name) is not None",
            )

            // set the schema as a python object
            interpreter.set("schema", schema)

            // parse the schema
            Logger.debug("Parsing the JSON with GQLSpection")
            interpreter.exec("parsed = GQLSchema(json=schema)")

            // initialize containing dicts
            interpreter.exec("queries = {}")
            interpreter.exec("mutations = {}")

            Logger.debug("Extracting data")
            // extract data
            Logger.debug("Extracting queries...")
            interpreter.exec(
                """
                for query in parsed.query.fields:
                    if not query.name: continue
                    if not is_valid_graphql_name(query.name): continue
                    queries[query.name] = parsed.generate_query(query, depth=$depth).to_string(pad=$pad)
                """.trimIndent(),
            )

            Logger.debug("Extracting mutations...")
            interpreter.exec(
                """
                for mutation in parsed.mutation.fields:
                    if not mutation.name: continue
                    if not is_valid_graphql_name(mutation.name): continue
                    mutations[mutation.name] = parsed.generate_mutation(mutation, depth=$depth).to_string(pad=$pad)
                """.trimIndent(),
            )

            // convert to json for easy transfer to Java
            interpreter.exec("json_queries = json.dumps(queries)")
            interpreter.exec("json_mutations = json.dumps(mutations)")

            Logger.debug("Fetching JSON data structures")
            val jsonQueries = interpreter.get("json_queries").asString()
            val jsonMutations = interpreter.get("json_mutations").asString()

            // convert back to maps
            Logger.debug("Parsing fetched JSON back to Java Maps")
            val mapType = object : TypeToken<Map<String, String>>() {}.type
            val queries: Map<String, String>
            val mutations: Map<String, String>
            try {
                queries = gson.fromJson<Map<String, String>>(jsonQueries, mapType)
                mutations = gson.fromJson<Map<String, String>>(jsonMutations, mapType)
            } catch (_: JsonSyntaxException) {
                Logger.error("Cannot parse JSON queries and mutations from (Py)GQLSpection")
                return null
            }

            // process pois
            var poisJson: String? = null
            if (config.getBoolean("report.poi") != false) {
                Logger.debug("POIs enabled, fetching...")
                // get enabled poi categories
                Logger.debug("Setting categories")
                interpreter.exec("categories = []")
                for (category in getEnabledPoiCategories()) {
                    interpreter.set("cat", category)
                    interpreter.exec("categories.append(cat)")
                }

                // get custom keywords
                Logger.debug("Setting keywords")
                interpreter.exec("keywords = []")
                for (keyword in (config.getString("report.poi.custom_keywords") ?: "").split('\n')) {
                    interpreter.set("kw", keyword)
                    interpreter.exec("keywords.append(cat)")
                }

                Logger.debug("Processing POIs")
                interpreter.exec("poi_json = json.dumps(parsed.points_of_interest(depth=$depth, categories=categories, keywords=keywords))")

                Logger.debug("Fetching JSON POIs")
                poisJson = interpreter.get("poi_json").asString()

                // POI Cleanup
                try {
                    interpreter.exec("del categories, keywords, cat, kw, poi_json")
                } catch (_: Exception) {
                    // Catch this in case one of the variables is not defined but do nothing about it
                }
            }

            // process cycle detection
            var cycleDetectionResults: String? = null
            if (config.getBoolean("report.cycles") != false) {
                Logger.debug("Cycle detection enabled, fetching...")
                interpreter.exec("from gqlspection import GQLCycleDetector")
                val cycleDepth = config.getInt("report.cycles.depth")
                interpreter.exec("cycle_detector = GQLCycleDetector(parsed, $cycleDepth)")
                interpreter.exec("cycle_detector.detect()")
                interpreter.exec("cycle_detection_results = cycle_detector.cycles_as_string()")
                cycleDetectionResults = interpreter.get("cycle_detection_results").asString()
            }

            // Cleanup
            Logger.debug("Parsing done, cleaning up...")
            interpreter.exec("del schema, parsed, queries, mutations, json_queries, json_mutations, cycle_detector, cycle_detection_results")

            return GQLSchemaMemoryBackedImpl(queries, mutations, poisJson, cycleDetectionResults)
        } catch (e: Exception) {
            Logger.info("GQLSpection failed to parse the JSON")
            Logger.info("Error: $e")
            // Cleanup
            try {
                interpreter.exec("del schema, parsed, queries, mutations, json_queries, json_mutations")
            } catch (_: Exception) {
                // Catch this in case one of the variables is not defined but do nothing about it
            }
            return null
        }
    }

    private fun _setLogLevel(level: String) {
        interpreter.set("log_level", level)
        interpreter.exec(
            "class DebugOrInfo(logging.Filter):\n" +
                "    def filter(self, record):\n" +
                "        return record.levelno in (logging.DEBUG, logging.INFO)",
        )
        interpreter.exec(
            "gql_log.setLevel(log_level)\n" +
                "formatter = logging.Formatter('[thread#%(thread)d %(filename)s:%(lineno)d :: %(funcName)s()]    %(message)s')\n" +
                "handler_stdout = logging.StreamHandler(sys.stdout)\n" +
                "handler_stdout.setFormatter(formatter)\n" +
                "handler_stdout.setLevel(logging.DEBUG)\n" +
                "handler_stdout.addFilter(DebugOrInfo())\n" +
                "handler_stderr = logging.StreamHandler(sys.stderr)\n" +
                "handler_stderr.setFormatter(formatter)\n" +
                "handler_stderr.setLevel(logging.WARNING)\n" +
                "del gql_log.handlers[:]\n" +
                "gql_log.addHandler(handler_stdout)\n" +
                "gql_log.addHandler(handler_stderr)",
        )
        interpreter.exec("del log_level")
    }

    override suspend fun parseSchema(schema: String): GQLSchemaMemoryBackedImpl? {
        lock.withLock {
            return this._parseSchema(schema)
        }
    }

    suspend fun setLogLevel(level: String) {
        lock.withLock {
            this._setLogLevel(level)
        }
    }

    override suspend fun unload() {
        lock.withLock {
            this._unload()
        }
    }
}
