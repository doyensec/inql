package inql.graphql

import graphql.language.BooleanValue
import graphql.language.FloatValue
import graphql.language.IntValue
import graphql.language.ObjectTypeDefinition
import graphql.language.ScalarTypeDefinition
import graphql.language.StringValue
import graphql.schema.Coercing
import graphql.schema.DataFetcher
import graphql.schema.GraphQLScalarType
import graphql.schema.TypeResolver
import graphql.schema.idl.FieldWiringEnvironment
import graphql.schema.idl.InterfaceWiringEnvironment
import graphql.schema.idl.MockedWiringFactory
import graphql.schema.idl.RuntimeWiring
import graphql.schema.idl.ScalarInfo
import graphql.schema.idl.TypeDefinitionRegistry
import graphql.schema.idl.TypeInfo
import graphql.schema.idl.UnionWiringEnvironment
import graphql.schema.idl.WiringFactory

/**
 * [RuntimeWiring.MOCKED_WIRING] uses [MockedWiringFactory] scalars that throw on serialize/parse and type resolvers
 * that throw. That breaks Federation SDL (custom scalars, interfaces, unions) when we run introspection to build
 * JSON for reports/cache. This wiring keeps PropertyDataFetchers from the mock factory but uses pass-through scalars
 * and deterministic type resolvers so schema inspection works.
 */
object SchemaInspectionRuntimeWiring {

    fun build(registry: TypeDefinitionRegistry): RuntimeWiring {
        val builder = RuntimeWiring.newRuntimeWiring()
        // Custom scalars live in scalarTypes, not in types() — ScalarTypeDefinition is never added to the types map.
        // scalars() merges spec definitions with user-defined scalars (see TypeDefinitionRegistry).
        for (def in registry.scalars().values.filterIsInstance<ScalarTypeDefinition>()) {
            if (!ScalarInfo.isGraphqlSpecifiedScalar(def.name)) {
                builder.scalar(passThroughScalar(def.name))
            }
        }
        builder.wiringFactory(InspectionWiringFactory(registry))
        return builder.build()
    }

    private fun passThroughScalar(name: String): GraphQLScalarType {
        val coercing = object : Coercing<Any, Any> {
            override fun serialize(dataFetcherResult: Any): Any = dataFetcherResult

            override fun parseValue(input: Any): Any = input

            override fun parseLiteral(input: Any): Any = when (input) {
                is StringValue -> input.value
                is BooleanValue -> input.isValue
                is IntValue -> input.value
                is FloatValue -> input.value
                else -> input.toString()
            }
        }
        return GraphQLScalarType.newScalar().name(name).coercing(coercing).build()
    }

    private class InspectionWiringFactory(
        private val registry: TypeDefinitionRegistry,
    ) : WiringFactory {
        private val mocked = MockedWiringFactory()

        override fun providesTypeResolver(environment: InterfaceWiringEnvironment): Boolean = true

        override fun getTypeResolver(environment: InterfaceWiringEnvironment): TypeResolver {
            val iface = environment.interfaceTypeDefinition
            val impl = registry.getImplementationsOf(iface).firstOrNull() as? ObjectTypeDefinition
                ?: return TypeResolver { null }
            val name = impl.name
            return TypeResolver { env -> env.schema.getObjectType(name) }
        }

        override fun providesTypeResolver(environment: UnionWiringEnvironment): Boolean = true

        override fun getTypeResolver(environment: UnionWiringEnvironment): TypeResolver {
            val union = environment.unionTypeDefinition
            val member = union.memberTypes.firstOrNull()
                ?: return TypeResolver { null }
            val typeName = TypeInfo.typeInfo(member).name
            return TypeResolver { env -> env.schema.getObjectType(typeName) }
        }

        override fun providesDataFetcher(environment: FieldWiringEnvironment): Boolean =
            mocked.providesDataFetcher(environment)

        override fun getDataFetcher(environment: FieldWiringEnvironment): DataFetcher<*> =
            mocked.getDataFetcher(environment)
    }
}
