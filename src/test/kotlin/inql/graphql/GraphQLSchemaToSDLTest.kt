package inql.graphql

import graphql.schema.idl.RuntimeWiring
import graphql.schema.idl.SchemaGenerator
import graphql.schema.idl.SchemaParser
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class GraphQLSchemaToSDLTest {

    /**
     * Builds a real GraphQLSchema from an SDL string using graphql-java's own
     * parser/generator, independent of InQL's introspection code. This lets us
     * test schemaToSDL() as a pure "schema in, SDL string out" round trip.
     */
    private fun buildSchema(sdl: String): graphql.schema.GraphQLSchema {
        val typeRegistry = SchemaParser().parse(sdl)
        val wiring = RuntimeWiring.newRuntimeWiring().build()
        return SchemaGenerator().makeExecutableSchema(typeRegistry, wiring)
    }

    @Test
    fun `schemaToSDL includes defined object types and fields`() {
        val sdl = """
            type Query {
                hello: String
                widget(id: ID!): Widget
            }

            type Widget {
                id: ID!
                name: String
                tags: [String!]!
            }
        """.trimIndent()

        val output = GraphQLSchemaToSDL.schemaToSDL(buildSchema(sdl))

        assertTrue(output.contains("type Query"))
        assertTrue(output.contains("type Widget"))
        assertTrue(output.contains("hello: String"))
        assertTrue(output.contains("id: ID!"))
        assertTrue(output.contains("tags: [String!]!"))
    }

    @Test
    fun `schemaToSDL includes custom scalar definitions`() {
        val sdl = """
            scalar DateTime

            type Query {
                now: DateTime
            }
        """.trimIndent()

        val wiring = RuntimeWiring.newRuntimeWiring()
            .scalar(
                graphql.schema.GraphQLScalarType.newScalar()
                    .name("DateTime")
                    .coercing(graphql.Scalars.GraphQLString.coercing)
                    .build(),
            )
            .build()
        val typeRegistry = SchemaParser().parse(sdl)
        val schema = SchemaGenerator().makeExecutableSchema(typeRegistry, wiring)

        val output = GraphQLSchemaToSDL.schemaToSDL(schema)
        assertTrue(output.contains("scalar DateTime"))
    }

    @Test
    fun `schemaToSDL includes enum definitions`() {
        val sdl = """
            enum Status {
                ACTIVE
                INACTIVE
            }

            type Query {
                status: Status
            }
        """.trimIndent()

        val output = GraphQLSchemaToSDL.schemaToSDL(buildSchema(sdl))

        assertTrue(output.contains("enum Status"))
        assertTrue(output.contains("ACTIVE"))
        assertTrue(output.contains("INACTIVE"))
    }

    @Test
    fun `schemaToSDL includes interface and implementing type`() {
        val sdl = """
            interface Node {
                id: ID!
            }

            type Widget implements Node {
                id: ID!
                name: String
            }

            type Query {
                node: Node
            }
        """.trimIndent()

        val typeRegistry = SchemaParser().parse(sdl)
        val wiring = RuntimeWiring.newRuntimeWiring()
            .type(
                graphql.schema.idl.TypeRuntimeWiring.newTypeWiring("Node")
                    .typeResolver { env -> env.schema.getObjectType("Widget") },
            )
            .build()
        val schema = SchemaGenerator().makeExecutableSchema(typeRegistry, wiring)
        val output = GraphQLSchemaToSDL.schemaToSDL(schema)

        assertTrue(output.contains("interface Node"))
        assertTrue(output.contains("Widget implements Node"))
    }
}
