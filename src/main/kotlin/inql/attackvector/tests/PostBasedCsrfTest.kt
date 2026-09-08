package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult

object PostBasedCsrfTest : ScannerTest {
    override val id = "post_csrf"
    override val name = "POST-based CSRF (URL-encoded body)"
    override val description = "Checks whether URL-encoded POST requests are accepted, which can enable CSRF."

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendFormUrlEncodedOperation("query { __typename }")
        return GraphqlProbe.classifyTransportProbe(
            name = name,
            exchange = exchange,
            executedDetail = "Server accepts POST requests with application/x-www-form-urlencoded GraphQL queries. " +
                "This may enable CSRF via simple HTML forms.",
            graphqlAcceptedDetail = "Server parsed a URL-encoded POST as GraphQL. This may enable CSRF via simple HTML forms.",
            rejectedDetail = "URL-encoded POST GraphQL query rejected or not supported.",
            isTransportRejection = GraphqlProbe::indicatesContentTypeRejection,
        )
    }
}
