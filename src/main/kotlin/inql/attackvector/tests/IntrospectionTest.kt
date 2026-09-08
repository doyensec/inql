package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
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
        val json = exchange.asJsonOrNull()
        val text = GraphqlProbe.responseText(json, exchange.body)

        if (isValidIntrospectionSchema(exchange.body)) {
            return TestResult(
                name,
                TestStatus.VULNERABLE,
                "Public introspection is enabled. Response contains a valid __schema with types.",
                evidence,
            )
        }

        if (GraphqlProbe.indicatesIntrospectionUnavailable(text)) {
            return TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                if (GraphqlProbe.indicatesIntrospectionDisabled(text) && !GraphqlProbe.indicatesUnknownField(text, "__schema")) {
                    "Server disabled introspection."
                } else {
                    "Introspection is not available (__schema is missing or not exposed on this schema)."
                },
                evidence,
            )
        }

        GraphqlProbe.classifyHttpFailure(name, exchange)?.let { return it }

        if (exchange.statusCode in 400..499 && !GraphqlProbe.isGraphqlJson(json)) {
            return TestResult(
                name,
                TestStatus.INACCESSIBLE,
                "Introspection probe inaccessible (HTTP ${exchange.statusCode}).",
                evidence,
            )
        }

        return TestResult(
            name,
            TestStatus.UNCERTAIN,
            "Introspection response could not be classified (HTTP ${exchange.statusCode}).",
            evidence,
        )
    }

    private fun isValidIntrospectionSchema(raw: String): Boolean {
        if (raw.isBlank()) return false
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
