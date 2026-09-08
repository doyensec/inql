package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object FieldSuggestionTest : ScannerTest {
    override val id = "field_suggestions"
    override val name = "Field Suggestions"
    override val description = "Checks whether validation errors leak schema details via field suggestions."

    private val suggestionPhrases = listOf(
        "did you mean",
        "perhaps you meant",
        "were you looking for",
        "suggestion",
        "suggestions",
        "hint",
    )

    override suspend fun run(context: ScanContext): TestResult {
        val query = "query { __schema { directive } }"
        val (response, evidence) = context.http.sendQueryExchange(query)
        val statusCode = evidence?.statusCode ?: 0

        if (response == null) {
            return TestResult(
                name,
                if (statusCode in 400..499) TestStatus.INACCESSIBLE else TestStatus.UNCERTAIN,
                when {
                    statusCode in 400..499 -> "Field suggestion probe inaccessible (HTTP $statusCode)."
                    statusCode in 500..599 -> "Server returned HTTP $statusCode for the suggestion probe."
                    else -> "No parseable JSON response for the suggestion probe."
                },
                evidence,
            )
        }

        val errors = response.optJSONArray("errors")
        val errorsText = errors?.toString() ?: ""

        return when {
            GraphqlProbe.containsAny(errorsText, suggestionPhrases) -> TestResult(
                name,
                TestStatus.VULNERABLE,
                "Server exposes field suggestions in validation errors (possible information disclosure).",
                evidence,
            )
            errors != null && errors.length() > 0 -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Validation error returned without field suggestions.",
                evidence,
            )
            statusCode in 500..599 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server returned HTTP $statusCode for the suggestion probe.",
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
