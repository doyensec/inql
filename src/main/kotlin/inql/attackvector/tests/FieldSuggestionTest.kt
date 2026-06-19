package inql.attackvector.tests

import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object FieldSuggestionTest : ScannerTest {
    override val id = "field_suggestions"
    override val name = "Field Suggestions (e.g., \"Did you mean...?\")"

    override suspend fun run(context: ScanContext): TestResult {
        val query = "query { __schema { directive } }"
        val (response, evidence) = context.http.sendQueryExchange(query)
        val errorsText = response.optJSONArray("errors")?.toString() ?: response.toString()

        val suggestionPatterns = listOf(
            "did you mean",
            "suggestion",
            "suggestions",
            "hint",
        )

        return when {
            suggestionPatterns.any { errorsText.contains(it, ignoreCase = true) } -> TestResult(
                name,
                TestStatus.CONFIRMED,
                "Server exposes field suggestions in validation errors (possible information disclosure).",
                evidence,
            )
            response.optJSONArray("errors") != null -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Validation error returned without field suggestions.",
                evidence,
            )
            response.length() == 0 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "No parseable response for the suggestion probe.",
                evidence,
            )
            else -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Unexpected response format for field suggestion probe.",
                evidence,
            )
        }
    }
}
