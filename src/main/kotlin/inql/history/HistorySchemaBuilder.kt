package inql.history

import burp.api.montoya.http.message.HttpRequestResponse
import graphql.schema.GraphQLSchema
import inql.graphql.GraphQLOperation
import inql.graphql.Utils

object HistorySchemaBuilder {
    fun buildFromRequestResponse(
        requestResponse: HttpRequestResponse,
        existingSchema: GraphQLSchema? = null,
    ): GraphQLSchema? {
        val request = requestResponse.request()
        val operation = Utils.getGraphQLOperation(request) ?: return null
        val response = requestResponse.response()
        val responseBody = response?.bodyToString()
        return buildFromOperation(operation, responseBody, existingSchema)
    }

    fun buildFromOperation(
        operation: GraphQLOperation,
        responseBody: String?,
        existingSchema: GraphQLSchema? = null,
    ): GraphQLSchema? {
        val rejectedFields = responseBody?.let { HistoryResponseValidator.getRejectedFieldNames(it) } ?: emptySet()
        val document = Utils.normalizeGraphQLDocument(operation.query)
        if (!Utils.isGraphQLDocument(document)) return null

        val errorHints = GraphQLErrorTypeHints.parse(responseBody)
        val responseDataBody = responseBody?.takeIf { ResponseDataParser.extractData(it) != null }

        val partialSchema = QueryAstToSchema.buildSchema(
            query = document,
            operationType = operation.operationType,
            rejectedFieldNames = rejectedFields,
            responseBody = responseDataBody,
            variables = operation.variables,
            errorHints = errorHints,
        ) ?: return null
        return SchemaMerger.merge(existingSchema, partialSchema)
    }
}
