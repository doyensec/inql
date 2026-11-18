package inql.fingerprinter

import inql.bruteforcer.ThrottledClient
import inql.Logger
import org.json.JSONObject

class EngineProbes(private val client: ThrottledClient) {

    suspend fun isGraphQLServer(): Boolean {
        val query = """
            query { __typename }
        """.trimIndent()
        val response = graphQuery(query)
        when {
            response.optJSONObject("data") != null -> return true
            response.has("errors") -> return true
            else -> return false
        }
    }

    suspend fun detectEngine(): String? {
        return when {
            engineInigo() -> "inigo"
            engineLighthouse() -> "lighthouse"
            engineCaliban() -> "caliban"
            engineLacinia() -> "lacinia"
//            engineJaal() -> "jaal" // TODO
            engineMorpheus() -> "morpheus-graphql"
            engineMercurius() -> "mercurius"
            engineGraphqlYoga() -> "graphql_yoga"
            engineAgoo() -> "agoo"
            engineTailcall() -> "tailcall"
            engineDgraph() -> "dgraph"
            engineGraphene() -> "graphene"
            engineAriadne() -> "ariadne"
            engineApollo() -> "apollo"
            engineAwsAppSync() -> "aws-appsync"
            engineHasura() -> "hasura"
            engineWpGraphql() -> "wpgraphql"
            engineGraphqlJava() -> "graphql-java"
            engineHypergraphql() -> "hypergraphql"
            engineRuby() -> "ruby-graphql"
            engineGraphqlPhp() -> "graphql-php"
            engineGqlGen() -> "gqlgen"
            engineGraphqlGo() -> "graphql-go"
            engineJuniper() -> "juniper"
            engineSangria() -> "sangria"
            engineDianaJl() -> "dianajl"
            engineStrawberry() -> "strawberry"
            engineTartiflette() -> "tartiflette"
            engineDirectus() -> "directus"
            engineAbsinthe() -> "absinthe-graphql"
            engineGraphqlDotNet() -> "graphql-dotnet"
            enginePgGraphql() -> "pg_graphql"
            engineHotChocolate() -> "hotchocolate"
            engineBallerina() -> "ballerina"
            engineFlutter() -> "flutter"
            else -> null
        }
    }

    private suspend fun graphQuery(query: String): JSONObject {
        return client.send(query)
    }

    private fun errorContains(resp: JSONObject, msg: String): Boolean {
        if (resp.optJSONArray("errors") != null) {
            return resp.optJSONArray("errors")?.let { errors ->
                for (i in 0 until errors.length()) {
                    if (errors.getJSONObject(i).toString().contains(msg)) return true
                }
                return false
            } ?: false
        } else if (resp.optString("error") != null) {
            return resp.toString().contains(msg)
        }

        return false
    }

    private suspend fun engineGraphqlYoga(): Boolean {
      Logger.debug("engineGraphqlYoga")
        val query = """
      subscription {
         __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "asyncExecutionResult[Symbol.asyncIterator] is not a function") || errorContains(resp, "Unexpected error.")
    }

    private suspend fun engineApollo(): Boolean {
      Logger.debug("engineApollo")
        var query = """
      query @skip {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Directive \\\"@skip\\\" argument \\\"if\\\" of type \\\"Boolean!\\\" is required, but it was not provided.")) {
            return true
        }

        query = """
      query @deprecated {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Directive \\\"@deprecated\\\" may not be used on QUERY.")
    }
    private suspend fun engineAwsAppSync(): Boolean {
      Logger.debug("engineAwsAppSync")
        val query = "query @skip { __typename }".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "MisplacedDirective")
    }
    private suspend fun engineGraphene(): Boolean {
      Logger.debug("engineGraphene")
        val query = """aaa""".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Syntax Error GraphQL (1:1)")
    }
    private suspend fun engineHasura(): Boolean {
      Logger.debug("engineHasura")
        var query = """
      query @cached {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)

        if (resp.optJSONObject("data")?.optString("__typename") == "query_root") {
            return true
        }
        query = """
     query {
       aaa
      }
    """
        resp = graphQuery(query)
        if (errorContains(resp, "field \"aaa\" not found in type: 'query_root'")) {
            return true
        }

        query = """
      query @skip {
        __typename
      }
    """
        resp = graphQuery(query)
        if (errorContains(resp, "directive \"skip\" is not allowed on a query")) {
            return true
        }

        query = """
      query {
        __schema
      }
    """
        resp = graphQuery(query)

        return errorContains(resp, "missing selection set for \"__Schema\"")
    }

    private suspend fun engineGraphqlPhp(): Boolean {
      Logger.debug("engineGraphqlPhp")
        var query = """
      query ! {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Syntax Error: Cannot parse the unexpected character \\\"?\\\".")) {
            return true
        }

        query = """
      query @deprecated {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Directive \\\"deprecated\\\" may not be used on \\\"QUERY\\\".")
    }

    private suspend fun engineRuby(): Boolean {
      Logger.debug("engineRuby")
        var query = """
     query @skip {
       __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")) {
            return true
        } else if (errorContains(resp, "Directive \'skip\' is missing required arguments: if")) {
            return true
        }

        query = """
     query @deprecated {
       __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "'@deprecated' can't be applied to queries")) {
            return true
        }
        query = """
      query {
       __typename {
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Parse error on \\\"}\\\" (RCURLY)")) {
            return true
        }
        query = """
      query {
        __typename @skip
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Directive 'skip' is missing required arguments: if")
    }

    private suspend fun engineHypergraphql(): Boolean {
      Logger.debug("engineHypergraphql")
        var query = """
     zzz {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Validation error of type InvalidSyntax: Invalid query syntax.")) {
            return true
        }
        query = """
      query {
        alias1:__typename @deprecated
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'")
    }

    private suspend fun engineGraphqlJava(): Boolean {
      Logger.debug("engineGraphqlJava")
        var query = """
     queryy  {
        __typename
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Invalid Syntax : offending token 'queryy'")) {
            return true
        }
        query = """
     query @aaa@aaa {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Validation error of type DuplicateDirectiveName: Directives must be uniquely named within a location.")) {
            return true
        }
        query = ""
        resp = graphQuery(query)
        return errorContains(resp, "Invalid Syntax : offending token '<EOF>'")
    }

    private suspend fun engineAriadne(): Boolean {
      Logger.debug("engineAriadne")
        var query = """
      query {
        __typename @abc
      }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Unknown directive '@abc'.") && resp.optJSONObject("data") != null){
            return true
        }

        query = ""
        resp = graphQuery(query)
        return errorContains(resp, "The query must be a string.")
    }

    private suspend fun engineWpGraphql(): Boolean {
      Logger.debug("engineWpGraphql")
        var query = ""
        var resp = graphQuery(query)
        if (errorContains(resp, "GraphQL Request must include at least one of those two parameters: \\\"query\\\" or \\\"queryId\\\"")) {
            return true
        }

        query = """
     query {
       alias1$1:__typename
     }
    """.trimIndent()
        resp = graphQuery(query)
        if (!errorContains(resp, "Syntax Error: Expected Name, found $")){
            return false
        }

        val ext = resp.optJSONObject("extensions") ?: return false
        val dbg = ext.optJSONArray("debug") ?: return false

        val debugMsg = JSONObject(dbg.get(0))
        val dbgMsgType = debugMsg.optString("type")
        val dbgMsgMessage = debugMsg.optString("message")

        return (dbgMsgType == "DEBUG_LOGS_INACTIVE" || dbgMsgMessage == "GraphQL Debug logging is not active. To see debug logs, GRAPHQL_DEBUG must be enabled.")
    }

    private suspend fun engineGqlGen(): Boolean {
      Logger.debug("engineGqlGen")
        var query = """
      query  {
      __typename {
    }
    """.trimIndent()
        var resp = graphQuery(query)

        if (errorContains(resp, "expected at least one definition")) {
            return true
        }
        query = """
      query  {
      alias^_:__typename {
    }
    """.trimIndent()
        resp = graphQuery(query)

        return errorContains(resp, "Expected Name, found <Invalid>")
    }
    private suspend fun engineGraphqlGo(): Boolean {
      Logger.debug("engineGraphqlGo")
        var query = """
      query {
      __typename {
      }
    """.trimIndent()
        var resp = graphQuery(query)

        if (errorContains(resp, "Unexpected empty IN")) {
            return true
        }

        query = ""
        resp = graphQuery(query)

        if (errorContains(resp, "Must provide an operation.")) {
            return true
        }

        query = """
      query {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        val typename = resp.optJSONObject("data")?.optString("__typename")
        return typename == "RootQuery"
    }

    private suspend fun engineJuniper(): Boolean {
      Logger.debug("engineJuniper")
        var query = """
      queryy {
        __typename
    }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Unexpected \"queryy\"")) {
            return true
        }

        query = ""
        resp = graphQuery(query)

        return errorContains(resp, "Unexpected end of input")
    }
    private suspend fun engineSangria(): Boolean {
      Logger.debug("engineSangria")
        val query = """
      queryy {
        __typename
    }
    """.trimIndent()
        val resp = graphQuery(query)
        val syntaxError = resp.optString("syntaxError")
        val msg = "Syntax error while parsing GraphQL query. Invalid input \"queryy\", expected ExecutableDefinition or TypeSystemDefinition"
        return syntaxError.contains(msg)
    }

    private suspend fun engineFlutter(): Boolean {
      Logger.debug("engineFlutter")
        val query = """
      query {
        __typename @deprecated
    }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Directive \"deprecated\" may not be used on FIELD.")
    }

    private suspend fun engineDianaJl(): Boolean {
      Logger.debug("engineDianaJl")
        val query = """queryy { __typename }""".trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \"queryy\"") || errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \\\"queryy\\\"")
    }

    private suspend fun engineStrawberry(): Boolean {
      Logger.debug("engineStrawberry")
        val query = """
      query @deprecated {
        __typename
      }""".trimIndent()
        val resp = graphQuery(query)
        return (errorContains(resp, "Directive '@deprecated' may not be used on query.")  && resp.keySet().contains("data"))
    }

    private suspend fun engineTartiflette(): Boolean {
      Logger.debug("engineTartiflette")
        var query = """
      query @a { __typename }
    """.trimIndent()
        var resp = graphQuery(query)
        if (errorContains(resp, "Unknow Directive < @a >.")) {
            return true
        }

        query = """
      query @skip { __typename }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Missing mandatory argument < if > in directive < @skip >.")) {
            return true
        }

        query = """
      query { graphwoof }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Field graphwoof doesn't exist on Query")) {
            return true
        }

        query = """
      query {
        __typename @deprecated
      }
    """.trimIndent()
        resp = graphQuery(query)
        if (errorContains(resp, "Directive < @deprecated > is not used in a valid location.")) {
            return true
        }

        query = """
      queryy {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)
        return errorContains(resp, "syntax error, unexpected IDENTIFIER")
    }

    private suspend fun engineTailcall(): Boolean {
      Logger.debug("engineTailcall")
        val query = """
      aa {
        __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)

        return errorContains(resp, "expected executable_definition")
    }

    private suspend fun engineDgraph(): Boolean {
      Logger.debug("engineDgraph")
        var query = """
      query {
        __typename @cascade
      }
    """.trimIndent()
        var resp = graphQuery(query)
        val typename = resp.optJSONObject("data")?.optString("__typename")
        if (typename == "Query") {
            return true
        }

        query = """
      query {
        __typename
      }
    """.trimIndent()
        resp = graphQuery(query)

        return errorContains(resp, "Not resolving __typename. There's no GraphQL schema in Dgraph. Use the /admin API to add a GraphQL schema")
    }

    private suspend fun engineDirectus(): Boolean {
      Logger.debug("engineDirectus")
        val query = ""

        val resp = graphQuery(query)
        val errors = resp.optJSONArray("errors")
        return (JSONObject(errors.get(0)).optJSONObject("extensions")?.optString("code") == "INVALID_PAYLOAD")
    }

    private suspend fun engineLighthouse(): Boolean {
      Logger.debug("engineLighthouse")
        val query = """
      query {
        __typename @include(if: falsee)
      }
    """.trimIndent()
        val resp = graphQuery(query)
        if (errorContains(resp, "Internal server error")) { // TODO or errorContains(resp, 'internal', part='category')):
            return true
        }

        return false
    }

    private suspend fun engineAgoo(): Boolean {
      Logger.debug("engineAgoo")
        val query = """
      query {
        zzz
      }
    """.trimIndent()
        val resp = graphQuery(query)
        return errorContains(resp, "eval error")
    }
    private suspend fun engineMercurius(): Boolean {
      Logger.debug("engineMercurius")
        val query = ""
        val resp = graphQuery(query)

        return errorContains(resp, "Unknown query") || errorContains(resp, "MER_ERR_GQL_VALIDATION")
    }
    private suspend fun engineMorpheus(): Boolean {
      Logger.debug("engineMorpheus")
        val query = """
      queryy {
          __typename
      }
    """.trimIndent()
        val resp = graphQuery(query)

        return (errorContains(resp, "expecting white space") || errorContains(resp, "offset"))
    }
    private suspend fun engineLacinia(): Boolean {
      Logger.debug("engineLacinia")
        val query = """
      query {
        inql
      }
    """.trimIndent()

        val resp = graphQuery(query)

        return errorContains(resp, "Cannot query field `inql' on type `QueryRoot'.")
    }

    // TODO
//    private suspend fun engineJaal(): Boolean {
//        var query = """{}""".trimIndent()
//        var resp = self.graph_query(self.url, payload=query, operation='{}')
//
//    if errorContains(resp, 'must have a single query') or errorContains(resp, 'offset'):
//      return true
//
//    return false
//    }

  private suspend fun engineCaliban(): Boolean {
    Logger.debug("engineCaliban")
    val query = """
        query {
            __typename
        }

        fragment woof on __Schema {
            directives {
                name
            }
        }
        """.trimIndent()

    val resp = graphQuery(query)

    return errorContains(resp, "Fragment 'woof' is not used in any spread")
}

  private suspend fun engineAbsinthe(): Boolean {
    Logger.debug("engineAbsinthe")
    val query = """
        query {
            inql
        }
        """.trimIndent()

    val resp = graphQuery(query)

    return errorContains(resp, "Cannot query field \\\"inql\\\" on type \\\"RootQueryType\\\".")
}
  private suspend fun engineGraphqlDotNet(): Boolean {
    Logger.debug("engineGraphqlDotNet")
    val query = "query @skip { __typename }".trimIndent()
    val resp = graphQuery(query)
    return errorContains(resp, "Directive 'skip' may not be used on Query.")
  }

  private suspend fun enginePgGraphql(): Boolean {
    Logger.debug("enginePgGraphql")
    val query = """query { __typename @skip(aa:true) }""".trimIndent()
    val resp = graphQuery(query)
    return errorContains(resp, "Unknown argument to @skip: aa")
  }

  private suspend fun engineHotChocolate(): Boolean {
    Logger.debug("engineHotChocolate")
    var query = """
        queryy  {
            __typename
        }
        """.trimIndent()
    var resp = graphQuery(query)
    if (errorContains(resp, "Unexpected token: Name.")) {
        return true
    }

    query = """
        query @aaa@aaa {
            __typename
        }
        """.trimIndent()
    resp = graphQuery(query)
    return errorContains(resp, "The specified directive `aaa` is not supported by the current schema.")
  }

  private suspend fun engineInigo(): Boolean {
    Logger.debug("engineInigo")
      val query = """
        query  {
            __typename
        }
        """.trimIndent()
      val resp = graphQuery(query)
      return resp.optJSONObject("extensions") != null && resp.optJSONObject("extensions").keySet().contains("inigo")
  }

  private suspend fun engineBallerina(): Boolean {
    Logger.debug("engineBallerina")
    val query = """
        query {
            __typename
            ...A
        }

        fragment A on Query {
            ...B
        }

        fragment B on Query {
            ...A
        }
        """.trimIndent()

    val resp = graphQuery(query)
    return errorContains(resp, "Cannot spread fragment \"A\" within itself via \"B\"")
    }

}
