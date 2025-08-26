package inql.graphql

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import graphql.GraphQL
import graphql.introspection.IntrospectionQuery
import graphql.introspection.IntrospectionResultToSchema
import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLSchema
import graphql.schema.idl.*
import graphql.schema.idl.errors.SchemaProblem
import inql.Config
import inql.Logger
import java.lang.reflect.Type

/*
    Simple wrapper class around GraphQLSchema that adds a few convenience methods
 */
class GQLSchema(jsonOrSdlSchema: String) {
    enum class OperationType {
        QUERY, MUTATION, SUBSCRIPTION
    }

    private var _jsonSchema: String? = null
    private var _sdlSchema: String? = null
    val schema: GraphQLSchema

    init {
        val schemaParser = SchemaParser()
        var typeDefinitionRegistry: TypeDefinitionRegistry

        // Check if it's a JSON introspection schema
        try {
            val type: Type = object : TypeToken<Map<String?, Any?>?>() {}.type
            var introspectionSchema : Map<String, Any> = Gson().fromJson(jsonOrSdlSchema, type)

            Logger.info("Parsing JSON schema")
            if (introspectionSchema.containsKey("data") && introspectionSchema["data"] is Map<*, *>) {
                @Suppress("UNCHECKED_CAST")
                introspectionSchema = introspectionSchema["data"] as Map<String, Any>
            }

            if (!introspectionSchema.containsKey("__schema") && introspectionSchema["__schema"] !is Map<*, *>) {
                throw RuntimeException("Could not identify schema.")
            }

            val schemaDocument = IntrospectionResultToSchema().createSchemaDefinition(introspectionSchema)
            typeDefinitionRegistry = schemaParser.buildRegistry(schemaDocument)
            this._jsonSchema = jsonOrSdlSchema
        } catch (e: JsonSyntaxException) {
            // It's not JSON, try to parse it as SDL
            Logger.info("Parsing SDL schema")
            try {
                typeDefinitionRegistry = schemaParser.parse(jsonOrSdlSchema)
            } catch (e: SchemaProblem) {
                Logger.error("SDL schema parsing error: ${e.message}")
                throw e
            }

            this._sdlSchema = jsonOrSdlSchema
        } catch (e: SchemaProblem) {
            Logger.error("JSON schema parsing error: ${e.message}")
            throw e
        }

        // TypeDefinitionRegistry -> GraphQLSchema
        val schemaGenerator = SchemaGenerator()
        this.schema = schemaGenerator.makeExecutableSchema(typeDefinitionRegistry, RuntimeWiring.MOCKED_WIRING)
    }

    val queries = schema.queryType.fields.associateBy { it.name }
    val mutations = if (schema.isSupportingMutations) schema.mutationType.fields.associateBy { it.name } else emptyMap()
    val subscriptions = if (schema.isSupportingSubscriptions) schema.subscriptionType.fields.associateBy { it.name } else emptyMap()
    private val queriesSdlCache = mutableMapOf<String, String>()

    val sdlSchema: String get() {
        if (_sdlSchema == null) {
            val printer = SchemaPrinter()
            _sdlSchema = printer.print(schema)
        }
        return _sdlSchema!!
    }

    val jsonSchema: String get() {
        if (_jsonSchema == null) {
            // Simulate an Introspection query to get the JSON schema
            val graphQL = GraphQL.newGraphQL(schema).build()
            val executionResult = graphQL.execute(IntrospectionQuery.INTROSPECTION_QUERY)
            _jsonSchema = Gson().toJson(executionResult.toSpecification())
        }
        return _jsonSchema!!
    }

    private fun getOperationAsText(operation: GraphQLFieldDefinition, type: OperationType, skipCache: Boolean = false): String {
        // Check cache first
        if (!skipCache && queriesSdlCache.containsKey(operation.name)) {
            return queriesSdlCache[operation.name]!!
        }

        // Get config
        val config = Config.getInstance()
        val depth = config.getInt("codegen.depth")!!
        val pad = config.getInt("codegen.pad")!!

        // Generate text
        val sdl = GQLQueryPrinter(operation, type, depth, pad).printSDL()
        if (!skipCache) {
            queriesSdlCache[operation.name] = sdl
        }
        return sdl
    }

    fun getOperationAsText(operationName: String, type: OperationType, skipCache: Boolean = false): String {
        val operation = when(type) {
            OperationType.QUERY -> this.queries[operationName]
            OperationType.MUTATION -> this.mutations[operationName]
            OperationType.SUBSCRIPTION -> this.subscriptions[operationName]
        }

        return getOperationAsText(operation!!, type, skipCache)
    }

    fun getQueryAsText(operationName: String, skipCache: Boolean = false) = getOperationAsText(operationName,
        OperationType.QUERY, skipCache)
    fun getMutationAsText(operationName: String, skipCache: Boolean = false) = getOperationAsText(operationName,
        OperationType.MUTATION, skipCache)
    fun getSubscriptionAsText(operationName: String, skipCache: Boolean = false) = getOperationAsText(operationName,
        OperationType.SUBSCRIPTION, skipCache)
}
