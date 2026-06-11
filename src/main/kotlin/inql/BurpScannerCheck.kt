package inql

import burp.Burp
import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import inql.graphql.scanners.BatchScanner

class BurpScannerCheck : ScanCheck {
    companion object {
        val TECH_CHECKS = arrayOf(
            """{"data":{"__schema":{""",
            "graphql-ws",
        )
        val CONSOLE_CHECKS = arrayOf(
            "GraphiQL",
            "GraphQL Playground",
            "GraphQL Console",
            "graphql-playground",
        )
        val URLS = arrayOf(
            "/graphql.php",
            "/graphql",
            "/graphiql",
            "/graphql/console/",
            "/swapi-graphql/",
            "/gql",
            "/graphql/subscriptions",
            "/graphql/subscription",
        )
    }

    /*
        helper method to search a response for occurrences of a literal match string
        and return a list of start/end offsets.

        :param response: response object to search for
        :param match: search term
        :return: matches
     */
    private fun getMatches(response: String, match: String): List<Marker> {
        val matches = ArrayList<Marker>()

        var start = 0
        while (start < response.length) {
            start = response.indexOf(match, start, ignoreCase = true)
            if (start == -1) break
            matches.add(Marker.marker(start, start + match.length))
            start += match.length
        }
        return matches
    }

    override fun activeAudit(
        baseRequestResponse: HttpRequestResponse,
        auditInsertionPoint: AuditInsertionPoint,
    ): AuditResult {
        val issues = ArrayList<AuditIssue>()

        if (baseRequestResponse.statusCode() !in 200..299) return AuditResult.auditResult()

        for (url in URLS) {
            // replace the path inside the old bytearray for the new request
            val newReq = baseRequestResponse.request().withPath(url)
            val result = Burp.Montoya.http().sendRequest(newReq)
            issues.addAll(this.passiveAudit(result).auditIssues())
        }

        // --- Batch Query Detection ---
        val batchScanner = BatchScanner(baseRequestResponse.request())
        val batchResults = batchScanner.scan()

        for (result in batchResults) {
            if (result.supported) {
                val typeLabel = when (result.type) {
                    BatchScanner.BatchType.ALIAS -> "Alias-Based"
                    BatchScanner.BatchType.ARRAY -> "Array-Based"
                }
                val description = when (result.type) {
                    BatchScanner.BatchType.ALIAS -> """
                        The GraphQL endpoint supports <b>alias-based query batching</b>.<br><br>
                        An attacker can combine multiple operations into a single HTTP request using
                        GraphQL aliases (e.g., <code>alias1: fieldName alias2: fieldName</code>).<br><br>
                        This can be exploited for:<br>
                        <ul>
                        <li>Brute-force attacks (e.g., 2FA bypass by sending thousands of codes in one request)</li>
                        <li>Rate-limit bypass (many operations counted as one HTTP request)</li>
                        <li>Denial of Service (resource-heavy queries multiplied via aliases)</li>
                        </ul>
                    """.trimIndent()
                    BatchScanner.BatchType.ARRAY -> """
                        The GraphQL endpoint supports <b>array-based query batching</b>.<br><br>
                        An attacker can send a JSON array of independent query objects in a single
                        HTTP request. Each query executes separately on the server.<br><br>
                        This can be exploited for:<br>
                        <ul>
                        <li>Brute-force attacks (e.g., thousands of login attempts in one request)</li>
                        <li>Rate-limit bypass (one HTTP request, many GraphQL operations)</li>
                        <li>Denial of Service (parallel execution of expensive queries)</li>
                        </ul>
                    """.trimIndent()
                }

                val remediation = """
                    Consider implementing:<br>
                    <ul>
                    <li>Query cost analysis / depth limiting</li>
                    <li>Per-operation rate limiting (not just per-HTTP-request)</li>
                    <li>Disable array batching if not needed (e.g., Apollo Server's
                        <code>allowBatchedHttpRequests: false</code>)</li>
                    <li>Limit the maximum number of aliases per query</li>
                    </ul>
                """.trimIndent()

                issues.add(
                    AuditIssue.auditIssue(
                        "GraphQL $typeLabel Batch Query Support Detected",
                        description,
                        remediation,
                        baseRequestResponse.url(),
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        """<ul>
                            <li><a href='https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'>OWASP API4 - Unrestricted Resource Consumption</a></li>
                            <li><a href='https://graphql.org/'>GraphQL Specification</a></li>
                        </ul>""",
                        AuditIssueSeverity.LOW,
                        if (result.response != null) {
                            listOf(baseRequestResponse)
                        } else {
                            emptyList()
                        },
                    ),
                )
            }
        }
        return AuditResult.auditResult(issues)
    }

    override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult {
        val issues = ArrayList<AuditIssue>()

        if (baseRequestResponse.statusCode() !in 200..299) return AuditResult.auditResult(issues)

        for (check in TECH_CHECKS) {
            // look for matches of our passive check grep string
            val matches = getMatches(baseRequestResponse.response().bodyToString(), check)
            if (matches.isNotEmpty()) {
                issues.add(
                    AuditIssue.auditIssue(
                        "GraphQL Technology",
                        """
                        The website is using GraphQL Technology!<br><br>"
                        GraphQL is an open-source data query and manipulation language for APIs, and a runtime for fulfilling queries with existing data. GraphQL was developed internally by Facebook in 2012 before being publicly released in 2015.<br><br>
                        It provides an efficient, powerful and flexible approach to developing web APIs, and has been compared and contrasted with REST and other web service architectures. It allows clients to define the structure of the data required, and exactly the same structure of the data is returned from the server, therefore preventing excessively large amounts of data from being returned, but this has implications for how effective web caching of query results can be. The flexibility and richness of the query language also adds complexity that may not be worthwhile for simple APIs. It consists of a type system, query language and execution semantics, static validation, and type introspection.<br><br>
                        GraphQL supports reading, writing (mutating) and subscribing to changes to data (realtime updates).
                        """.trimIndent(),
                        "<ul><li><a href='https://graphql.org/'>GraphQL</a></li></ul>",
                        baseRequestResponse.url(),
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.FIRM,
                        "Not posing any imminent security risk.",
                        "<ul><li><a href='https://graphql.org/'>GraphQL</a></li></ul>",
                        AuditIssueSeverity.INFORMATION,
                        listOf(baseRequestResponse.withResponseMarkers(matches)),
                    ),
                )
            }
        }
        for (check in CONSOLE_CHECKS) {
            // look for matches of our passive check grep string
            val matches = getMatches(baseRequestResponse.response().bodyToString(), check)
            if (matches.isNotEmpty()) {
                issues.add(
                    AuditIssue.auditIssue(
                        "Exposed GraphQL Development Console",
                        """
                        GraphQL is a query language for APIs and a runtime for fulfilling queries with existing data.<br><br>
                        <b>GraphiQL/GraphQL Playground</b> are in-browser tools for writing, validating, and testing GraphQL queries.<br><br>
                        The response contains the following string: <b>$check</b>
                        """.trimIndent(),
                        """
                        Remove the GraphQL development console from web-application in a production stage.<br><br>
                        Disable GraphiQL<br>
                        <pre>if (process.env.NODE_ENV === 'development') {</pre></br>
                        <pre>  app.all(</pre></br>
                        <pre>    '/graphiql',</pre></br>
                        <pre>    graphiqlExpress({</pre></br>
                        <pre>      endpointURL: '/graphql',</pre></br>
                        <pre>    }),</pre></br>
                        <pre>  );</pre></br>
                        <pre>}</pre>
                        """.trimIndent(),
                        baseRequestResponse.url(),
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.FIRM,
                        "Not posing any imminent security risk.",
                        """
                        <ul>
                        <li><a href='https://graphql.org/'>GraphQL</a></li>
                        <li><a href='https://github.com/graphql/graphiql'>GraphiQL</a></li>
                        <li><a href='https://github.com/prisma/graphql-playground'>GraphQL Playground</a></li>
                        </ul>
                        """.trimIndent(),
                        AuditIssueSeverity.LOW,
                        listOf(baseRequestResponse.withResponseMarkers(matches)),
                    ),
                )
            }
        }
        return AuditResult.auditResult(issues)
    }

    override fun consolidateIssues(newIssue: AuditIssue, existingIssue: AuditIssue): ConsolidationAction {
        return if (existingIssue.httpService().host() == newIssue.httpService().host() &&
            existingIssue.httpService().port() == newIssue.httpService().port()
        ) {
            ConsolidationAction.KEEP_EXISTING
        } else {
            ConsolidationAction.KEEP_BOTH
        }
    }
}
