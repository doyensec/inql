package inql.attackvector.tests

import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object GetMutationSupportTest : ScannerTest {
    override val id = "get_mutation"
    override val name = "Support for GET Mutations"

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendGetOperation("mutation { __typename }")
        val evidence = exchange.toEvidence()
        val json = exchange.asJsonOrNull()

        return when {
            exchange.statusCode in 500..599 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server returned HTTP ${exchange.statusCode} for GET mutation (ambiguous).",
                evidence,
            )
            json?.optJSONObject("data")?.optString("__typename")?.isNotBlank() == true -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "GET mutation appears to execute (data returned). This is a security misconfiguration.",
                evidence,
            )
            GetQuerySupportTest.indicatesMethodRejection(json, exchange.body) -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "GET mutation rejected.",
                evidence,
            )
            json?.optJSONArray("errors") != null -> {
                val errors = json.optJSONArray("errors").toString().lowercase()
                if (errors.contains("mutation") && errors.contains("get")) {
                    TestResult(name, TestStatus.NOT_VULNERABLE, "Server rejects GET mutations explicitly.", evidence)
                } else {
                    TestResult(
                        name,
                        TestStatus.NOT_VULNERABLE,
                        "GET mutation rejected with validation errors.",
                        evidence,
                    )
                }
            }
            else -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "GET mutation response could not be classified (HTTP ${exchange.statusCode}).",
                evidence,
            )
        }
    }
}
