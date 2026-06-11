package inql.graphql.scanners

import burp.api.montoya.http.message.responses.HttpResponse
import com.google.gson.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`

class BatchScannerTest {

    // ──────────────────────────────────────────────
    //  Helper: create a mock HttpResponse
    // ──────────────────────────────────────────────
    private fun mockResponse(statusCode: Short, body: String): HttpResponse {
        val resp = mock(HttpResponse::class.java)
        `when`(resp.statusCode()).thenReturn(statusCode)
        `when`(resp.bodyToString()).thenReturn(body)
        return resp
    }

    // ══════════════════════════════════════════════
    //  PAYLOAD GENERATION
    // ══════════════════════════════════════════════

    @Nested
    @DisplayName("Alias batch payload generation")
    inner class AliasBatchPayload {

        @Test
        fun `payload is valid JSON with a query field`() {
            val body = BatchScanner.buildAliasBatchBody()
            val json = JsonParser.parseString(body)
            assertTrue(json.isJsonObject)
            assertTrue(json.asJsonObject.has("query"))
        }

        @Test
        fun `query contains both alias names`() {
            val body = BatchScanner.buildAliasBatchBody()
            val query = JsonParser.parseString(body).asJsonObject["query"].asString
            assertTrue(query.contains("inql_batch_alias1"))
            assertTrue(query.contains("inql_batch_alias2"))
        }

        @Test
        fun `query uses __typename as the probe field`() {
            val body = BatchScanner.buildAliasBatchBody()
            val query = JsonParser.parseString(body).asJsonObject["query"].asString
            assertTrue(query.contains("__typename"))
        }
    }

    @Nested
    @DisplayName("Array batch payload generation")
    inner class ArrayBatchPayload {

        @Test
        fun `payload is a valid JSON array`() {
            val body = BatchScanner.buildArrayBatchBody()
            val json = JsonParser.parseString(body)
            assertTrue(json.isJsonArray)
        }

        @Test
        fun `array contains exactly 2 elements`() {
            val body = BatchScanner.buildArrayBatchBody()
            val arr = JsonParser.parseString(body).asJsonArray
            assertEquals(2, arr.size())
        }

        @Test
        fun `each element has a query field`() {
            val body = BatchScanner.buildArrayBatchBody()
            val arr = JsonParser.parseString(body).asJsonArray
            arr.forEach { elem ->
                assertTrue(elem.isJsonObject)
                assertTrue(elem.asJsonObject.has("query"))
            }
        }

        @Test
        fun `each query contains __typename`() {
            val body = BatchScanner.buildArrayBatchBody()
            val arr = JsonParser.parseString(body).asJsonArray
            arr.forEach { elem ->
                val query = elem.asJsonObject["query"].asString
                assertTrue(query.contains("__typename"))
            }
        }
    }

    // ══════════════════════════════════════════════
    //  ALIAS BATCH RESPONSE ANALYSIS
    // ══════════════════════════════════════════════

    @Nested
    @DisplayName("Alias batch response analysis")
    inner class AliasBatchAnalysis {

        @Test
        fun `detects supported when both aliases present in data`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": "Query",
                        "inql_batch_alias2": "Query"
                    }
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertTrue(supported)
        }

        @Test
        fun `detects not supported when only one alias present`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": "Query"
                    }
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("alias2=false"))
        }

        @Test
        fun `detects not supported on HTTP 400`() {
            val resp = mockResponse(400, """{"errors": [{"message": "bad request"}]}""")
            val (supported, detail) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("400"))
        }

        @Test
        fun `detects not supported on HTTP 500`() {
            val resp = mockResponse(500, "Internal Server Error")
            val (supported, _) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertFalse(supported)
        }

        @Test
        fun `detects not supported when response is not JSON`() {
            val resp = mockResponse(200, "<html>Not Found</html>")
            val (supported, detail) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("parse") || detail.contains("not a JSON"))
        }

        @Test
        fun `detects not supported when data field is missing`() {
            val body = """{"errors": [{"message": "syntax error"}]}"""
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("No 'data' field"))
        }

        @Test
        fun `reports warning when aliases resolve but errors are present`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": "Query",
                        "inql_batch_alias2": "Query"
                    },
                    "errors": [{"message": "rate limited"}]
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("errors present"))
        }

        @Test
        fun `succeeds when errors array is empty`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": "Query",
                        "inql_batch_alias2": "Query"
                    },
                    "errors": []
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertTrue(supported)
        }

        @Test
        fun `handles null data values gracefully`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": null,
                        "inql_batch_alias2": null
                    }
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertTrue(supported, "Null values still indicate the server processed both aliases")
        }
    }

    // ══════════════════════════════════════════════
    //  ARRAY BATCH RESPONSE ANALYSIS
    // ══════════════════════════════════════════════

    @Nested
    @DisplayName("Array batch response analysis")
    inner class ArrayBatchAnalysis {

        @Test
        fun `detects supported when response is array of 2 results`() {
            val body = """
                [
                    {"data": {"__typename": "Query"}},
                    {"data": {"__typename": "Query"}}
                ]
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertTrue(supported)
        }

        @Test
        fun `detects not supported when server returns single object`() {
            val body = """{"data": {"__typename": "Query"}}"""
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("not a JSON array"))
        }

        @Test
        fun `detects not supported when server returns error object`() {
            val body = """
                {
                    "errors": [{"message": "Batching is not allowed"}]
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("error object"))
        }

        @Test
        fun `detects not supported on HTTP 400`() {
            val resp = mockResponse(400, "Bad Request")
            val (supported, detail) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("400"))
        }

        @Test
        fun `detects not supported when array has wrong count`() {
            val body = """
                [
                    {"data": {"__typename": "Query"}}
                ]
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("Expected 2"))
        }

        @Test
        fun `detects not supported when array elements lack data field`() {
            val body = """
                [
                    {"errors": [{"message": "fail"}]},
                    {"errors": [{"message": "fail"}]}
                ]
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, detail) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("missing 'data'"))
        }

        @Test
        fun `handles empty response body`() {
            val resp = mockResponse(200, "")
            val (supported, detail) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
            assertTrue(detail.contains("parse") || detail.contains("not a JSON"))
        }

        @Test
        fun `handles HTTP 405 Method Not Allowed`() {
            val resp = mockResponse(405, "Method Not Allowed")
            val (supported, _) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertFalse(supported)
        }

        @Test
        fun `accepts response with extra fields in array elements`() {
            val body = """
                [
                    {"data": {"__typename": "Query"}, "extensions": {"tracing": {}}},
                    {"data": {"__typename": "Query"}, "extensions": {"tracing": {}}}
                ]
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeArrayBatchResponse(resp)
            assertTrue(supported)
        }
    }

    // ══════════════════════════════════════════════
    //  EDGE CASES & CROSS-CUTTING
    // ══════════════════════════════════════════════

    @Nested
    @DisplayName("Edge cases")
    inner class EdgeCases {

        @Test
        fun `alias analysis handles deeply nested data`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": {"nested": {"deep": true}},
                        "inql_batch_alias2": {"nested": {"deep": true}}
                    }
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertTrue(supported)
        }

        @Test
        fun `alias analysis handles numeric values`() {
            val body = """
                {
                    "data": {
                        "inql_batch_alias1": 42,
                        "inql_batch_alias2": 99
                    }
                }
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeAliasBatchResponse(resp)
            assertTrue(supported)
        }

        @Test
        fun `array analysis handles mixed success and error elements`() {
            // Both elements have "data", even though one also has errors
            val body = """
                [
                    {"data": {"__typename": "Query"}},
                    {"data": null, "errors": [{"message": "not found"}]}
                ]
            """.trimIndent()
            val resp = mockResponse(200, body)
            val (supported, _) = BatchScanner.analyzeArrayBatchResponse(resp)
            // Still counts as supported — server processed the array
            assertTrue(supported)
        }

        @Test
        fun `alias payload is stable across invocations`() {
            val body1 = BatchScanner.buildAliasBatchBody()
            val body2 = BatchScanner.buildAliasBatchBody()
            assertEquals(body1, body2)
        }

        @Test
        fun `array payload is stable across invocations`() {
            val body1 = BatchScanner.buildArrayBatchBody()
            val body2 = BatchScanner.buildArrayBatchBody()
            assertEquals(body1, body2)
        }
    }
}
