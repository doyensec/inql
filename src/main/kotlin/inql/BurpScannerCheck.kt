package inql

import burp.Burp
import burp.api.montoya.core.Marker
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.scancheck.ActiveScanCheck
import burp.api.montoya.scanner.scancheck.PassiveScanCheck
import burp.api.montoya.scanner.scancheck.ScanCheckType
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

/**
 * GraphQL detection checks for Burp Scanner.
 *
 * - Passive check ([Passive], [ScanCheckType.PER_REQUEST]): looks for GraphQL / GraphQL console markers in responses.
 * - Active check ([Active], [ScanCheckType.PER_HOST]): requests a fixed list of well-known GraphQL paths and runs the
 *   passive check on the responses. The probed paths don't depend on the insertion point, so it runs once per host.
 *
 * On Burp versions without the typed scan check API (before 2025.6) [register] falls back to the deprecated
 * `registerScanCheck` with [Legacy].
 */
class BurpScannerCheck private constructor() {
    companion object {
        private const val PASSIVE_CHECK_NAME = "InQL: GraphQL technology and console detection"
        private const val ACTIVE_CHECK_NAME = "InQL: GraphQL endpoint discovery"

        /** Registers the passive and active checks with Burp Scanner. */
        @Suppress("DEPRECATION")
        fun register(scanner: Scanner) {
            val checks = BurpScannerCheck()
            try {
                checks.registerTyped(scanner)
            } catch (e: LinkageError) {
                // NoSuchMethodError / NoClassDefFoundError: Burp predates the typed scan check API (2025.6).
                Logger.debug("Typed scan check API unavailable, using legacy registerScanCheck: ${e.message}")
                scanner.registerScanCheck(checks.Legacy())
            }
        }

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

    private fun activeAudit(
        baseRequestResponse: HttpRequestResponse,
        sendRequest: (HttpRequest) -> HttpRequestResponse,
    ): AuditResult {
        val issues = ArrayList<AuditIssue>()

        // No status check on the base response: the probes only replace the path, so they are meaningful whatever
        // the base request returned. With PER_HOST this runs once per host, so skipping a non-2xx base request
        // would skip the whole host. Each probe's own response is still filtered for 2xx by passiveAudit().
        for (url in URLS) {
            // replace the path inside the old bytearray for the new request
            val newReq = baseRequestResponse.request().withPath(url)
            val result = sendRequest(newReq)
            issues.addAll(this.passiveAudit(result).auditIssues())
        }
        return AuditResult.auditResult(issues)
    }

    private fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult {
        val issues = ArrayList<AuditIssue>()

        if (baseRequestResponse.response() == null || baseRequestResponse.response().statusCode() !in 200..299) {
            return AuditResult.auditResult(issues)
        }

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
                        baseRequestResponse.request().url(),
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
                        baseRequestResponse.request().url(),
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

    /** Reports each issue once per host:port. */
    private fun consolidate(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction {
        return if (existingIssue.httpService().host() == newIssue.httpService().host() &&
            existingIssue.httpService().port() == newIssue.httpService().port()
        ) {
            ConsolidationAction.KEEP_EXISTING
        } else {
            ConsolidationAction.KEEP_BOTH
        }
    }

    private inner class Passive : PassiveScanCheck {
        override fun checkName(): String = PASSIVE_CHECK_NAME

        override fun doCheck(baseRequestResponse: HttpRequestResponse): AuditResult =
            passiveAudit(baseRequestResponse)

        override fun consolidateIssues(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction =
            consolidate(existingIssue, newIssue)
    }

    private inner class Active : ActiveScanCheck {
        override fun checkName(): String = ACTIVE_CHECK_NAME

        override fun doCheck(
            baseRequestResponse: HttpRequestResponse,
            insertionPoint: AuditInsertionPoint?,
            http: Http,
        ): AuditResult = activeAudit(baseRequestResponse) { http.sendRequest(it) }

        override fun consolidateIssues(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction =
            consolidate(existingIssue, newIssue)
    }

    /** Adapter for Burp versions that only support the deprecated [Scanner.registerScanCheck]. */
    @Suppress("DEPRECATION")
    private inner class Legacy : ScanCheck {
        override fun activeAudit(
            baseRequestResponse: HttpRequestResponse,
            auditInsertionPoint: AuditInsertionPoint,
        ): AuditResult = activeAudit(baseRequestResponse) { Burp.Montoya.http().sendRequest(it) }

        override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult =
            this@BurpScannerCheck.passiveAudit(baseRequestResponse)

        // Note: the legacy interface passes (newIssue, existingIssue).
        override fun consolidateIssues(newIssue: AuditIssue, existingIssue: AuditIssue): ConsolidationAction =
            consolidate(existingIssue, newIssue)
    }

    private fun registerTyped(scanner: Scanner) {
        scanner.registerPassiveScanCheck(Passive(), ScanCheckType.PER_REQUEST)
        scanner.registerActiveScanCheck(Active(), ScanCheckType.PER_HOST)
    }
}
