package inql.attackvector

import org.json.JSONObject

enum class RejectionSignal { NONE, WEAK, STRONG }

fun maxSignal(a: RejectionSignal, b: RejectionSignal): RejectionSignal = if (a.ordinal >= b.ordinal) a else b

object GraphqlProbe {
    fun isGraphqlJson(json: JSONObject?): Boolean {
        return json != null && (json.has("data") || json.has("errors"))
    }

    fun hasTypenameData(json: JSONObject?): Boolean {
        return json?.optJSONObject("data")?.optString("__typename")?.isNotBlank() == true
    }

    fun responseText(json: JSONObject?, body: String): String {
        return (json?.toString() ?: body).lowercase()
    }

    fun containsAny(text: String, phrases: List<String>): Boolean {
        val haystack = text.lowercase()
        return phrases.any { haystack.contains(it) }
    }

    fun signalFor(text: String, strong: List<String>, weak: List<String>): RejectionSignal {
        val t = text.lowercase()
        if (containsAny(t, strong)) return RejectionSignal.STRONG
        if (containsAny(t, weak)) return RejectionSignal.WEAK
        return RejectionSignal.NONE
    }

    private val getTransportRejectionStrongPhrases = listOf(
        "method not allowed",
        "must be post",
        "only post",
        "http method is not allowed",
        "get query is not allowed",
        "get queries are not allowed",
        "get request is not allowed",
        "get requests are not allowed",
        "queries cannot be performed via get",
        "graphql queries must be posted",
        "only supports post",
        "only support post",
        "get is not supported",
        "get not supported",
    )

    private val getTransportRejectionWeakPhrases = listOf(
        "get query",
        "get request",
        "get queries",
        "get requests",
    )

    fun getTransportRejectionSignal(text: String): RejectionSignal {
        val t = text.lowercase()
        val strongOrWeak = signalFor(t, getTransportRejectionStrongPhrases, getTransportRejectionWeakPhrases)
        if (strongOrWeak != RejectionSignal.NONE) return strongOrWeak
        return if (t.contains("get") && t.contains("not allowed")) RejectionSignal.WEAK else RejectionSignal.NONE
    }

    private val getMutationRefusalStrongPhrases = listOf(
        "mutations can only be sent using post",
        "mutation can only be sent using post",
        "mutations must be sent using post",
        "mutation must be sent using post",
        "mutations are not allowed via get",
        "mutation is not allowed via get",
        "http get is not allowed for mutation",
        "get is not allowed for mutation",
        "schema is not configured for mutations",
        "schema is not configured for mutation",
        "mutation type is not configured",
        "schema does not define a mutation",
        "no mutation type",
    )

    private val getMutationRefusalWeakPhrases = listOf(
        "not allowed",
        "cannot",
        "can't",
        "only support",
        "only supports",
        "queries only",
        "must be post",
        "use post",
        "not supported",
    )

    fun getMutationRefusalSignal(text: String): RejectionSignal {
        val t = text.lowercase()
        if (containsAny(t, getMutationRefusalStrongPhrases)) return RejectionSignal.STRONG
        if (!t.contains("mutation")) return RejectionSignal.NONE
        if (t.contains("get") || t.contains("post")) {
            if (containsAny(t, getMutationRefusalWeakPhrases)) return RejectionSignal.WEAK
        }
        return RejectionSignal.NONE
    }

    private val contentTypeRejectionStrongPhrases = listOf(
        "content-type",
        "content type",
        "unsupported media",
        "must be json",
        "application/json required",
        "expected application/json",
        "unsupported content type",
        "invalid content type",
    )

    private val contentTypeRejectionWeakPhrases = listOf(
        "application/json",
        "invalid request",
        "bad request",
        "parse",
    )

    fun contentTypeRejectionSignal(text: String): RejectionSignal {
        return signalFor(text, contentTypeRejectionStrongPhrases, contentTypeRejectionWeakPhrases)
    }

    /**
     * Gateway/format rejections wrapped as GraphQL `errors` (e.g. Stellate INVALID_QUERY).
     * These mean the body was not accepted as a GraphQL operation — not transport success.
     */
    fun indicatesInvalidGraphqlRequest(text: String): Boolean {
        return containsAny(
            text,
            listOf(
                "did not contain a valid graphql request",
                "does not contain a valid graphql request",
                "not contain a valid graphql",
                "invalid graphql request",
                "not a valid graphql request",
                "request is not a valid graphql",
                "malformed graphql request",
                "unable to parse graphql",
                "could not parse graphql",
                "failed to parse graphql",
                "cannot parse the request",
                "could not parse the request",
                "failed to parse the request",
                "no query document",
                "must provide a query string",
                "must provide a query",
                "query is missing",
                "missing query",
                "empty request body",
                "request body is empty",
                "batch queries and apq",
                "batch queries are not currently supported",
                "batch queries are not supported",
                "apq request are not currently supported",
                "apq requests are not currently supported",
                "automatic persisted queries are not",
            ),
        )
    }

    fun indicatesAuthFailure(text: String): Boolean {
        return containsAny(
            text,
            listOf(
                "unauthorized",
                "unauthenticated",
                "authentication required",
                "not authenticated",
                "access denied",
                "forbidden",
                "permission denied",
                "not authorized",
                "invalid token",
                "missing authorization",
            ),
        )
    }

    fun indicatesIntrospectionDisabled(text: String): Boolean {
        val t = text.lowercase()
        if (containsAny(
                t,
                listOf(
                    "introspection is not allowed",
                    "introspection is disabled",
                    "introspection disabled",
                    "introspection has been disabled",
                    "introspection has been turned off",
                    "__schema is not allowed",
                    "to enable introspection",
                ),
            )
        ) {
            return true
        }
        return t.contains("introspection") && containsAny(
            t,
            listOf(
                "not allowed",
                "disabled",
                "forbidden",
                "not permitted",
                "turned off",
                "unavailable",
            ),
        )
    }

    /**
     * True when `__schema` is missing/unavailable — introspection (and introspection-based
     * depth/complexity probes) cannot run. Distinct from a generic validation error.
     */
    fun indicatesIntrospectionUnavailable(text: String): Boolean {
        if (indicatesIntrospectionDisabled(text)) return true
        val t = text.lowercase()
        if (!t.contains("__schema")) return false
        return containsAny(
            t,
            listOf(
                "doesn't exist",
                "does not exist",
                "cannot query field",
                "unknown field",
                "undefined field",
                "is not defined",
                "not defined",
                "is not a field of",
                "cannot query",
            ),
        )
    }

    /** True when the response is an unknown/missing field validation error (optionally for [fieldName]). */
    fun indicatesUnknownField(text: String, fieldName: String? = null): Boolean {
        val t = text.lowercase()
        val looksUnknown = containsAny(
            t,
            listOf(
                "doesn't exist",
                "does not exist",
                "cannot query field",
                "unknown field",
                "undefined field",
                "is not defined",
                "not defined",
                "is not a field of",
            ),
        )
        if (!looksUnknown) return false
        if (fieldName == null) return true
        return t.contains(fieldName.lowercase())
    }

    fun indicatesFederationUnavailable(text: String): Boolean {
        val t = text.lowercase()
        val fieldMissing = t.contains("_service") || t.contains("\"sdl\"") || Regex("""\bsdl\b""").containsMatchIn(t)
        if (!fieldMissing) return false
        return containsAny(
            t,
            listOf(
                "cannot query field",
                "unknown field",
                "undefined field",
                "does not exist",
                "doesn't exist",
                "not defined",
                "cannot query",
                "unknown type",
                "field is not defined",
                "is not a field of",
            ),
        )
    }

    fun classifyHttpFailure(name: String, exchange: ScanHttpClient.HttpExchange): TestResult? {
        val evidence = exchange.toEvidence()
        return when {
            exchange.statusCode in 500..599 -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server returned HTTP ${exchange.statusCode}.",
                evidence,
            )
            exchange.statusCode == 401 || exchange.statusCode == 403 || exchange.statusCode == 404 -> TestResult(
                name,
                TestStatus.INACCESSIBLE,
                "Probe inaccessible (HTTP ${exchange.statusCode}).",
                evidence,
            )
            else -> null
        }
    }

    fun classifyTransportProbe(
        name: String,
        exchange: ScanHttpClient.HttpExchange,
        executedDetail: String,
        graphqlAcceptedDetail: String,
        rejectedDetail: String,
        isTransportRejection: (String) -> RejectionSignal,
    ): TestResult {
        val evidence = exchange.toEvidence()
        val json = exchange.asJsonOrNull()
        val text = responseText(json, exchange.body)
        val status = exchange.statusCode

        if (status in 500..599) {
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server returned HTTP $status.",
                evidence,
            )
        }

        if (hasTypenameData(json)) {
            return TestResult(name, TestStatus.VULNERABLE, executedDetail, evidence)
        }

        classifyHttpFailure(name, exchange)?.let { return it }

        if (indicatesAuthFailure(text)) {
            return TestResult(
                name,
                TestStatus.INACCESSIBLE,
                "Probe inaccessible (authentication/authorization required).",
                evidence,
            )
        }

        val rejection = isTransportRejection(text)
        if (rejection == RejectionSignal.STRONG || indicatesInvalidGraphqlRequest(text) || status == 405) {
            return TestResult(name, TestStatus.NOT_VULNERABLE, rejectedDetail, evidence)
        }

        // GraphQL JSON on success or validation-style 400 means the transport parsed the operation.
        // Format/gateway rejections above must not reach here (Stellate-style INVALID_QUERY, etc.).
        if (isGraphqlJson(json) && (status in 200..299 || status == 400)) {
            return TestResult(name, TestStatus.VULNERABLE, graphqlAcceptedDetail, evidence)
        }

        if (rejection == RejectionSignal.WEAK) {
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "$rejectedDetail (evidence was generic wording; verify manually).",
                evidence,
            )
        }

        if (status in 400..499) {
            return TestResult(
                name,
                TestStatus.INACCESSIBLE,
                "Probe inaccessible (HTTP $status).",
                evidence,
            )
        }

        return TestResult(
            name,
            TestStatus.UNCERTAIN,
            "Response could not be classified (HTTP $status).",
            evidence,
        )
    }
}
