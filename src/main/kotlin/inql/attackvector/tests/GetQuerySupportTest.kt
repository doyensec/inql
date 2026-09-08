package inql.attackvector.tests

import inql.attackvector.GraphqlProbe
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object GetQuerySupportTest : ScannerTest {
    override val id = "get_query"
    override val name = "Support for GET Queries"
    override val description = "Checks whether GraphQL queries can be executed over HTTP GET."

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendGetOperation("query { __typename }")
        return GraphqlProbe.classifyTransportProbe(
            name = name,
            exchange = exchange,
            executedDetail = "GET query executed successfully (data.__typename present).",
            graphqlAcceptedDetail = "GET accepted a GraphQL query document.",
            rejectedDetail = "GET query rejected (method or transport not allowed).",
            isTransportRejection = GraphqlProbe::indicatesGetTransportRejection,
        )
    }
}
