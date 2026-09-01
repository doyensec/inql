package inql.utils

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JsonPrettifierTest {

    @Test
    fun `prettify formats compact JSON object with indentation`() {
        val input = """{"a":1,"b":"two","c":[1,2,3]}"""
        val result = JsonPrettifier.prettify(input)

        // Pretty-printed output should contain newlines (compact input has none)
        assertTrue(result.contains("\n"), "Expected pretty-printed output to contain line breaks")
        assertTrue(result.contains("\"a\": 1"))
        assertTrue(result.contains("\"b\": \"two\""))
    }

    @Test
    fun `prettify preserves nested structure`() {
        val input = """{"outer":{"inner":{"value":true}}}"""
        val result = JsonPrettifier.prettify(input)

        assertTrue(result.contains("\"outer\""))
        assertTrue(result.contains("\"inner\""))
        assertTrue(result.contains("true"))
    }

    @Test
    fun `prettify handles JSON arrays at top level`() {
        val input = """[{"id":1},{"id":2}]"""
        val result = JsonPrettifier.prettify(input)

        assertTrue(result.contains("\"id\": 1"))
        assertTrue(result.contains("\"id\": 2"))
    }

    @Test
    fun `prettify does not HTML-escape special characters`() {
        // GsonBuilder().disableHtmlEscaping() should keep '<', '>', '&' unescaped
        val input = """{"query":"query { field(arg: \"<test>&data\") }"}"""
        val result = JsonPrettifier.prettify(input)

        assertTrue(result.contains("<test>&data"), "Expected special characters to remain unescaped")
    }

    @Test
    fun `prettify falls back to original string on malformed JSON`() {
        val input = "{not valid json at all"
        val result = JsonPrettifier.prettify(input)

        assertEquals(input, result)
    }

    @Test
    fun `prettify treats empty string as JSON null rather than throwing`() {
        // Gson's lenient parser treats an empty/blank input as JsonNull (not a parse
        // error), so prettify("") returns the literal string "null" rather than
        // falling back to the original input. The fallback path is only exercised
        // by genuinely malformed JSON — see the malformed-JSON test above.
        val result = JsonPrettifier.prettify("")
        assertEquals("null", result)
    }

    @Test
    fun `prettify handles primitive JSON values`() {
        assertEquals("true", JsonPrettifier.prettify("true").trim())
        assertEquals("42", JsonPrettifier.prettify("42").trim())
        assertEquals("\"plain\"", JsonPrettifier.prettify("\"plain\"").trim())
    }
}
