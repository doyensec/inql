package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.RejectionSignal
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import inql.attackvector.maxSignal

object GetMutationSupportTest : ScannerTest {
    override val id = "get_mutation"
    override val name = "Support for GET Mutations"
    override val description = "Checks whether GraphQL mutations can be executed over HTTP GET."

    override suspend fun run(context: ScanContext): TestResult {
        val queryExchange = context.http.sendGetOperation("query { __typename }")
        val queryText = GraphqlProbe.responseText(queryExchange.asJsonOrNull(), queryExchange.body)
        if (queryExchange.statusCode == 405 || GraphqlProbe.getTransportRejectionSignal(queryText) == RejectionSignal.STRONG) {
            return TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "GET GraphQL queries are not accepted, so GET mutations are not exposed.",
                queryExchange.toEvidence(),
            )
        }

        val exchange = context.http.sendGetOperation("mutation { __typename }")
        return GraphqlProbe.classifyTransportProbe(
            name = name,
            exchange = exchange,
            executedDetail = "GET mutation executed (data returned). This is a security misconfiguration.",
            graphqlAcceptedDetail = "GET accepted a mutation document. Mutations over GET are enabled at the transport layer.",
            rejectedDetail = "Server rejects GET mutations.",
            isTransportRejection = { text ->
                maxSignal(GraphqlProbe.getMutationRefusalSignal(text), GraphqlProbe.getTransportRejectionSignal(text))
            },
        )
    }
}
