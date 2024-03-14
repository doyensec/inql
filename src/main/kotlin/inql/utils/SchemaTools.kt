import com.google.gson.Gson
import graphql.GraphQL
import graphql.introspection.IntrospectionQuery
import graphql.introspection.IntrospectionResultToSchema
import graphql.schema.*
import graphql.schema.idl.*
import inql.Logger
import java.io.StringReader

object SchemaTools {
    private val gson = Gson()
    private val schemaParser = SchemaParser()
    private val introspectionConverter = IntrospectionResultToSchema()

    fun jsonToSdl(json: String): String? {
        @Suppress("UNCHECKED_CAST")
        var introspectionResult : Map<String, Any> = gson.fromJson(json, Map::class.java) as Map<String, Any>

        // if introspectionResult starts with "data" key, then move one level deeper (to __schema)
        if (introspectionResult.containsKey("data")) {
            @Suppress("UNCHECKED_CAST")
            introspectionResult = introspectionResult["data"] as Map<String, Any>
        }

        // make sure the top level key is __schema
        if (introspectionResult.containsKey("__schema")) {
            Logger.debug("Converting JSON schema to SDL")
            val schemaSDL = introspectionConverter.createSchemaDefinition(introspectionResult)
            Logger.debug("Converted JSON schema to SDL")
            return SchemaPrinter().print(schemaSDL)
        } else {
            Logger.debug("Could not convert JSON schema to SDL")
        }
        return null
    }

    // This mocking factory class is used to bypass the requirement for a runtime data fetcher
    private class MockedWiringFactory : WiringFactory {
        override fun providesScalar(environment: ScalarWiringEnvironment): Boolean =
            !ScalarInfo.isGraphqlSpecifiedScalar(environment.scalarTypeDefinition.name)

        override fun getScalar(environment: ScalarWiringEnvironment): GraphQLScalarType =
            GraphQLScalarType.newScalar()
                .name(environment.scalarTypeDefinition.name)
                .coercing(object : Coercing<Any, Any> {
                    @Deprecated("TODO: Figure out upgrade path for this method", level=DeprecationLevel.WARNING)
                    override fun parseValue(input: Any): Any = throw UnsupportedOperationException()
                    @Deprecated("TODO: Figure out upgrade path for this method", level=DeprecationLevel.WARNING)
                    override fun parseLiteral(input: Any): Any = throw UnsupportedOperationException()
                    @Deprecated("TODO: Figure out upgrade path for this method", level=DeprecationLevel.WARNING)
                    override fun serialize(dataFetcherResult: Any): Any = throw UnsupportedOperationException()
                })
                .build()

        override fun providesTypeResolver(environment: InterfaceWiringEnvironment): Boolean = true
        override fun getTypeResolver(environment: InterfaceWiringEnvironment): TypeResolver = TypeResolver { _ -> null }

        override fun providesTypeResolver(environment: UnionWiringEnvironment): Boolean = true
        override fun getTypeResolver(environment: UnionWiringEnvironment): TypeResolver = TypeResolver { _ -> null }
    }

    fun sdlToJson(schemaSDL: String): String = executeQuery(schemaSDL, IntrospectionQuery.INTROSPECTION_QUERY)

    fun executeQuery(schemaSDL: String, query: String): String {
        // Parse the provided SDL schema
        val typeDefinitionRegistry = schemaParser.parse(StringReader(schemaSDL))

        // Prepare the wiring using our mocked factory
        val runtimeWiring = RuntimeWiring.newRuntimeWiring()
            .wiringFactory(MockedWiringFactory())
            .build()

        // Generate the schema
        val schema: GraphQLSchema = SchemaGenerator().makeExecutableSchema(typeDefinitionRegistry, runtimeWiring)

        // Create a GraphQL instance and execute the query
        val graphQL = GraphQL.newGraphQL(schema).build()
        val executionResult = graphQL.execute(query)

        // Convert the execution result to a JSON string
        val gson = Gson()
        return gson.toJson(executionResult.toSpecification())
    }
}
