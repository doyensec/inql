package inql.graphql.gqlspection

import inql.Logger
import inql.graphql.CacheableSchema
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.python.core.Py
import org.python.util.PythonInterpreter
import java.io.IOException
import java.util.concurrent.Executors

class InterpreterWrapper(private val jythonDispatcher: ExecutorCoroutineDispatcher) {
    val interpreter: PythonInterpreter = PythonInterpreter()
    private val lock = Mutex()

    suspend fun <T> withInterpreter(block: PythonInterpreter.() -> T): T = withContext(jythonDispatcher) {
        lock.withLock {
            interpreter.block()
        }
    }
}

// This class should only have simple methods that call the Python interpreter
// Do not put any logic here, and avoid methods calling other methods

class PyGQLSpection private constructor() : IGQLSpection {
    companion object {
        private var instance: PyGQLSpection? = null
        fun getInstance(): PyGQLSpection {
            if (instance == null) instance = PyGQLSpection()
            return instance as PyGQLSpection
        }
    }

    val jythonDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private val interpreterWrapper = InterpreterWrapper(jythonDispatcher)
    private val maxCacheSize = 4

    init {
        runBlocking {
            initInterpreter()
        }
    }

    private suspend fun initInterpreter() = interpreterWrapper.withInterpreter {
        exec(
            """
            import sys
            reload(sys)
            sys.setdefaultencoding('UTF8')
        """.trimIndent()
        )

        setOut(System.out)
        setErr(System.err)

        exec(
            """
            from gqlspection import log as gql_log
            from gqlspection import GQLSchema, GQLCycleDetector
            from collections import OrderedDict
            import logging
            import json

            cache = OrderedDict()
            max_cache_size = $maxCacheSize

            def create_and_cache_schema(schema_id, json_string):
                cache[schema_id] = GQLSchema(json=json_string)
                if len(cache) > max_cache_size:
                    cache.popitem(last=False)
                return cache[schema_id]

            def has_schema(schema_id):
                return schema_id in cache

            def get_schema(schema_id):
                return cache.get(schema_id)
        """.trimIndent()
        )
    }

    // Sets `schema` to the GQLSchema object in the Python interpreter and executes the given command
    private suspend fun execute(schema: CacheableSchema, command: String) = interpreterWrapper.withInterpreter {
        try {
            if (eval("has_schema(${schema.id})").asInt() == 0) {
                // We're trying to limit the number of times data is copied between Kotlin and Python
                set("schemaJson", schema.json)
                Logger.info("Executing: create_and_cache_schema(${schema.id}, schemaJson)")
                exec("schema = create_and_cache_schema(${schema.id}, schemaJson)")
                exec("del schemaJson")
            } else {
                Logger.info("Executing: get_schema(${schema.id})")
                exec("schema = get_schema(${schema.id})")
            }
            Logger.info("Executing: $command")
            exec(command)
        } catch (e: IOException) {
            Logger.error("Error executing command: $command due to IOException. The Python code might be too large.")
            e.printStackTrace()
        }
    }

    private suspend inline fun <reified T> getObject(name: String): T? = interpreterWrapper.withInterpreter {
        val pyObject = get(name)
        Py.tojava(pyObject, T::class.java)
    }

    private suspend fun setObject(name: String, value: Any?) = interpreterWrapper.withInterpreter {
        set(name, value)
    }

    // The rest of the functions should be rewritten to use the above methods

    suspend fun listQueries(schema: CacheableSchema): List<String> {
        this.execute(
            schema,
            """
            queries = [query.name for query in schema.query.fields if query.name]
            """.trimIndent(),
        )
        return this.getObject("queries") ?: emptyList()
    }

    suspend fun listMutations(schema: CacheableSchema): List<String> {
        this.execute(
            schema,
            """
            mutations = [mutation.name for mutation in schema.mutation.fields if mutation.name]
            """.trimIndent(),
        )
        return this.getObject("mutations") ?: emptyList()
    }

    suspend fun getQuery(schema: CacheableSchema, name: String, depth: Int, pad: Int): String? {
        setObject("name", name)
        this.execute(
            schema,
            """
            query = schema.generate_query(name, $depth).to_string(pad=$pad)
            """.trimIndent(),
        )
        return this.getObject("query")
    }

    suspend fun getMutation(schema: CacheableSchema, name: String, depth: Int, pad: Int): String? {
        setObject("name", name)
        this.execute(
            schema,
            """
            mutation = schema.generate_mutation(name, $depth).to_string(pad=$pad)
            """.trimIndent(),
        )
        return this.getObject("mutation")
    }

    suspend fun getPointsOfInterest(
        schema: CacheableSchema,
        categories: List<String>,
        keywords: List<String>,
        depth: Int
    ): String {
        this.setObject("categories", categories)
        this.setObject("keywords", keywords)
        this.execute(
            schema,
            """
            poi_json = json.dumps(schema.points_of_interest(depth=$depth, categories=categories, keywords=keywords))
            """.trimIndent(),
        )
        return this.getObject("poi_json") ?: ""
    }

    suspend fun getCycleDetectionResults(schema: CacheableSchema, maxDepth: Int): String {
        this.execute(
            schema,
            """
            cycle_detector = GQLCycleDetector(schema, max_depth=$maxDepth)
            cycle_detector.detect()
            cycle_detection_results = cycle_detector.cycles_as_string()
            """.trimIndent(),
        )
        return this.getObject("cycle_detection_results") ?: ""
    }

    override suspend fun unload() = interpreterWrapper.withInterpreter {
        cleanup()
        close()
        instance = null
    }

    override suspend fun setLogLevel(level: String) = interpreterWrapper.withInterpreter {
        set("log_level", level)
        exec(
            """
            class DebugOrInfo(logging.Filter):
                def filter(self, record):
                    return record.levelno in (logging.DEBUG, logging.INFO)
                    
            gql_log.setLevel(log_level)
            formatter = logging.Formatter('[thread#%(thread)d %(filename)s:%(lineno)d :: %(funcName)s()]    %(message)s')
            handler_stdout = logging.StreamHandler(sys.stdout)
            handler_stdout.setFormatter(formatter)
            handler_stdout.setLevel(logging.DEBUG)
            handler_stdout.addFilter(DebugOrInfo())
            handler_stderr = logging.StreamHandler(sys.stderr)
            handler_stderr.setFormatter(formatter)
            handler_stderr.setLevel(logging.WARNING)
            del gql_log.handlers[:]
            gql_log.addHandler(handler_stdout)
            gql_log.addHandler(handler_stderr)
            """.trimIndent()
        )
        exec("del log_level")
    }
}
