package inql.attackvector.tests

import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import org.json.JSONObject

object GetQuerySupportTest : ScannerTest {
    override val id = "get_query"
    override val name = "Support for GET Queries"

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendGetOperation("query { __typename }")
        val evidence = exchange.toEvidence()
        val json = exchange.asJsonOrNull()

        return when {
            exchange.statusCode in 500..599 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server returned HTTP ${exchange.statusCode} for GET query (ambiguous).",
                evidence,
            )
            json?.optJSONObject("data")?.optString("__typename")?.isNotBlank() == true -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "GET query executed successfully (data.__typename present).",
                evidence,
            )
            indicatesMethodRejection(json, exchange.body) -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "GET query rejected (method or transport not allowed).",
                evidence,
            )
            else -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "GET query response could not be classified (HTTP ${exchange.statusCode}).",
                evidence,
            )
        }
    }

    internal fun indicatesMethodRejection(json: JSONObject?, body: String): Boolean {
        val text = (json?.toString() ?: body).lowercase()
        return listOf(
            "get query",
            "get request",
            "method not allowed",
            "must be post",
            "only post",
            "not allowed",
        ).any { text.contains(it) }
    }
}
