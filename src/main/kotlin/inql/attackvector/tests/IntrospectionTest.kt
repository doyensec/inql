package inql.attackvector.tests

import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import org.json.JSONObject

object IntrospectionTest : ScannerTest {
    override val id = "introspection"
    override val name = "Public Schema Introspection"
    override val description = "Checks whether the full GraphQL schema can be retrieved via introspection."

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendIntrospectionExchange()
        val evidence = exchange.toEvidence()
        val raw = exchange.body.takeIf { it.isNotBlank() }

        if (raw == null || exchange.statusCode >= 400) {
            return TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Introspection query rejected or returned errors (HTTP ${exchange.statusCode}).",
                evidence,
            )
        }

        val json = exchange.asJsonOrNull()
        if (json?.has("errors") == true) {
            return TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Introspection query rejected or returned errors.",
                evidence,
            )
        }

        return if (isValidIntrospectionSchema(raw)) {
            TestResult(
                name,
                TestStatus.VULNERABLE,
                "Public introspection is enabled. Response contains a valid __schema with types.",
                evidence,
            )
        } else {
            TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Introspection query returned 200 but response could not be verified as a valid schema.",
                evidence,
            )
        }
    }

    private fun isValidIntrospectionSchema(raw: String): Boolean {
        return try {
            val json = JSONObject(raw)
            val schema = json.optJSONObject("data")?.optJSONObject("__schema") ?: return false
            val types = schema.optJSONArray("types") ?: return false
            types.length() > 0
        } catch (_: Exception) {
            false
        }
    }
}
