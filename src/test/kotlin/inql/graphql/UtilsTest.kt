package inql.graphql

import graphql.Scalars
import graphql.schema.GraphQLList
import graphql.schema.GraphQLNonNull
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class UtilsTest {

    // formatComment(String, Int) overload does not exist on the dev branch —
    // only the List<String> overload remains (see below).

    // ---- formatComment(List<String>, Int) ----

    @Test
    fun `formatComment list overload prefixes each element`() {
        val result = Utils.formatComment(listOf("alpha", "beta"))
        assertEquals(listOf("# alpha", "# beta"), result)
    }

    @Test
    fun `formatComment list overload wraps long elements`() {
        val longLine = "word ".repeat(30).trim()
        val result = Utils.formatComment(listOf(longLine), maxLength = 20)

        assertTrue(result.size > 1)
        for (line in result) {
            assertTrue(line.startsWith("# "))
        }
    }

    @Test
    fun `formatComment list overload handles empty list`() {
        val result = Utils.formatComment(emptyList())
        assertEquals(emptyList<String>(), result)
    }

    // ---- unwrapType ----

    @Test
    fun `unwrapType returns the same type when not wrapped`() {
        val type = GraphQLObjectType.newObject().name("Widget").build()
        assertEquals(type, Utils.unwrapType(type))
    }

    @Test
    fun `unwrapType strips a single NonNull wrapper`() {
        val inner = Scalars.GraphQLString
        val wrapped = GraphQLNonNull.nonNull(inner)
        assertEquals(inner, Utils.unwrapType(wrapped))
    }

    @Test
    fun `unwrapType strips nested List and NonNull wrappers`() {
        // [String!]! -> should unwrap all the way down to GraphQLString
        val inner = Scalars.GraphQLString
        val wrapped = GraphQLNonNull.nonNull(GraphQLList.list(GraphQLNonNull.nonNull(inner)))
        assertEquals(inner, Utils.unwrapType(wrapped))
    }

    // ---- isBuiltInScalarType ----

    @Test
    fun `isBuiltInScalarType returns true for all five built-in scalars`() {
        assertTrue(Utils.isBuiltInScalarType(Scalars.GraphQLInt))
        assertTrue(Utils.isBuiltInScalarType(Scalars.GraphQLFloat))
        assertTrue(Utils.isBuiltInScalarType(Scalars.GraphQLString))
        assertTrue(Utils.isBuiltInScalarType(Scalars.GraphQLBoolean))
        assertTrue(Utils.isBuiltInScalarType(Scalars.GraphQLID))
    }

    @Test
    fun `isBuiltInScalarType returns false for a custom scalar`() {
        val customScalar = GraphQLScalarType.newScalar()
            .name("DateTime")
            .coercing(Scalars.GraphQLString.coercing)
            .build()
        assertFalse(Utils.isBuiltInScalarType(customScalar))
    }
}
