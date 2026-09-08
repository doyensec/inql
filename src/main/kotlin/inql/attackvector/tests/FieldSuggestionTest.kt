package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import inql.graphql.GraphQLRequestTransformer
import graphql.language.Field
import graphql.language.OperationDefinition
import graphql.parser.Parser
import org.json.JSONObject

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
        val (response, evidence) = context.http.sendQueryExchange("query { __schema { directive } }")
        val errorsText = response?.optJSONArray("errors")?.toString() ?: ""

        if (response != null && GraphqlProbe.indicatesIntrospectionUnavailable(errorsText)) {
            return runFallbackProbe(context) ?: TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Field suggestion probing requires introspection; __schema is not available on this schema, " +
                    "and no field from the loaded request could be used to probe the real schema instead.",
                evidence,
            )
        }

        return classify(response, evidence)
    }

    private suspend fun runFallbackProbe(context: ScanContext): TestResult? {
        val payload = try {
            GraphQLRequestTransformer.parsePayload(context.http.baseRequest)
        } catch (_: Exception) {
            null
        }
        val fieldName = payload?.let { findTopLevelFieldName(it.query) } ?: return null
        val typo = misspell(fieldName)
        val (response, evidence) = context.http.sendQueryExchange("query { $typo }")
        return classify(response, evidence, realFieldName = fieldName)
    }

    private fun findTopLevelFieldName(query: String): String? {
        return try {
            Parser().parseDocument(query).definitions
                .filterIsInstance<OperationDefinition>()
                .firstOrNull()
                ?.selectionSet
                ?.selections
                ?.filterIsInstance<Field>()
                ?.firstOrNull()
                ?.name
        } catch (_: Exception) {
            null
        }
    }

    private fun misspell(fieldName: String): String {
        if (fieldName.length < 2) return "${fieldName}qz"
        val mid = fieldName.length / 2
        return fieldName.substring(0, mid) + "qz" + fieldName.substring(mid)
    }

    private fun classify(response: JSONObject?, evidence: TestEvidence?, realFieldName: String? = null): TestResult {
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

        if (realFieldName != null && errors != null && errors.length() > 0 &&
            !GraphqlProbe.indicatesUnknownField(errorsText)
        ) {
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "The probe field coincidentally matched a real field on the schema, so field-suggestion " +
                    "behavior could not be tested from this probe.",
                evidence,
            )
        }

        val hasSuggestion = GraphqlProbe.containsAny(errorsText, suggestionPhrases) &&
            (realFieldName == null || errorsText.lowercase().contains(realFieldName.lowercase()))

        return when {
            hasSuggestion -> TestResult(
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
