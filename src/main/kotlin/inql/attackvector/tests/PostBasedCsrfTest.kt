package inql.attackvector.tests

import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object PostBasedCsrfTest : ScannerTest {
    override val id = "post_csrf"
    override val name = "POST-based CSRF (URL-encoded body)"

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendFormUrlEncodedOperation("query { __typename }")
        val evidence = exchange.toEvidence()
        val json = exchange.asJsonOrNull()

        return when {
            exchange.statusCode in 500..599 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server returned HTTP ${exchange.statusCode} for URL-encoded POST query (ambiguous).",
                evidence,
            )
            json?.optJSONObject("data")?.optString("__typename")?.isNotBlank() == true -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "Server accepts POST requests with application/x-www-form-urlencoded GraphQL queries. " +
                    "This may enable CSRF via simple HTML forms.",
                evidence,
            )
            indicatesRejection(json, exchange.body) -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "URL-encoded POST GraphQL query rejected or not supported.",
                evidence,
            )
            else -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "URL-encoded POST response could not be classified (HTTP ${exchange.statusCode}).",
                evidence,
            )
        }
    }

    private fun indicatesRejection(json: org.json.JSONObject?, body: String): Boolean {
        val text = (json?.toString() ?: body).lowercase()
        return listOf(
            "content-type",
            "content type",
            "application/json",
            "unsupported media",
            "invalid request",
            "parse",
            "must be json",
            "bad request",
        ).any { text.contains(it) } || (json?.has("errors") == true && json.optJSONObject("data") == null)
    }
}
