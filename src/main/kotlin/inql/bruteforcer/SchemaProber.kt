package inql.bruteforcer

import org.json.JSONObject

/** An error with its location: a column on the one-line query, or the alias index named in Hasura's path. */
internal class ProbeError(val evidence: List<Evidence>, val column: Int?, val alias: Int?) {
    val located get() = column != null || alias != null
}

internal class Probe(val passed: Boolean, val errors: List<ProbeError>, private val ranges: List<IntRange>) {
    val evidence get() = errors.flatMap { it.evidence }
    fun segmentErrors(i: Int) = errors.filter { (it.column != null && i in ranges.indices && it.column in ranges[i]) || it.alias == i }

    /** True when segment [i] produced no error and every error could be located. */
    fun segmentPassed(i: Int) = passed || (errors.isNotEmpty() && errors.all { it.located } && segmentErrors(i).isEmpty())
}

internal class SchemaProber(
    private val client: ThrottledClient,
    private val stepArguments: (Path, Step.Field) -> Map<String, String>,
) {
    companion object {
        const val SENTINEL = "____i_n_q_l____"
        private const val SECOND_SENTINEL = "____i_n_q_l_2____"

        /** Unknown root field that keeps mutation and subscription probes from executing; distinct from [SENTINEL]. */
        private const val NO_EXECUTION_FIELD = "____inql_no_execution____"

        private val ALIAS_REGEX = Regex("""\binql(\d+)\b""")
    }

    var leafModifiersPrinted: Boolean? = null

    var compositeModifiersPrinted: Boolean? = null

    /** The server reports only the first validation error (Hasura), so names are probed sequentially. */
    var singleError = false
        private set

    /** `__typename` is `String!` and `__schema` is `__Schema!`: servers printing them bare strip type modifiers. */
    suspend fun calibrate() {
        probe("query { __typename { $SENTINEL } }").evidence.filterIsInstance<Evidence.LeafSelection>()
            .firstOrNull { it.field == "__typename" && it.type != null }?.let { leafModifiersPrinted = it.type!!.endsWith("!") }
        probe("query { __schema }").evidence.filterIsInstance<Evidence.MissingSelection>()
            .firstOrNull { it.field == "__schema" }?.let { compositeModifiersPrinted = it.type.endsWith("!") }
        singleError = probe("query { $SENTINEL $SECOND_SENTINEL }").evidence.filterIsInstance<Evidence.UnknownField>().size == 1
    }

    suspend fun probeSegments(path: Path, segments: List<String>, variables: Map<String, String> = emptyMap()): Probe {
        val (query, ranges) = build(path, segments, variables)
        return probe(query, ranges)
    }

    fun wrap(path: Path, inner: String): String = build(path, listOf(inner)).first

    /** Builds a one-line query for [segments] at [path] and the 1-based column range of each segment. */
    private fun build(path: Path, segments: List<String>, variables: Map<String, String> = emptyMap()): Pair<String, List<IntRange>> {
        val definitions = if (variables.isEmpty()) "" else variables.entries.joinToString(", ", "(", ")") { "\$${it.key}: ${it.value}" }
        val prefix = StringBuilder("${path.operation}$definitions { ")
        path.steps.forEachIndexed { i, step ->
            when (step) {
                is Step.Field -> {
                    val args = stepArguments(Path(path.operation, path.steps.take(i)), step)
                    prefix.append(step.name)
                    if (args.isNotEmpty()) prefix.append(args.entries.joinToString(", ", "(", ")") { "${it.key}: ${it.value}" })
                    prefix.append(" { ")
                }
                is Step.Fragment -> prefix.append("... on ${step.type} { ")
            }
        }
        val ranges = mutableListOf<IntRange>()
        val body = StringBuilder()
        segments.forEachIndexed { i, segment ->
            if (i > 0) body.append(' ')
            val start = prefix.length + body.length + 1
            body.append(segment)
            ranges += start until start + segment.length
        }
        // The unknown root field comes last so servers reporting only the first error still report the probe.
        val noExecution = if (path.operation != "query") " $NO_EXECUTION_FIELD" else ""
        return (prefix.toString() + body + " }".repeat(path.steps.size) + noExecution + " }") to ranges
    }

    suspend fun probe(query: String, ranges: List<IntRange> = emptyList()): Probe {
        val response = client.send(query)
        val errors = response.optJSONArray("errors")
        val parsed = (0 until (errors?.length() ?: 0)).mapNotNull { i ->
            val error = errors!!.optJSONObject(i) ?: return@mapNotNull null
            val location = error.optJSONArray("locations")?.optJSONObject(0)
            val path = error.optJSONObject("extensions")?.optString("path")?.takeIf { it.startsWith("$") }
            ProbeError(
                ErrorEvidence.parse(error.optString("message", ""), path),
                location?.takeIf { it.optInt("line") == 1 }?.optInt("column"),
                path?.let { ALIAS_REGEX.find(it)?.groupValues?.get(1)?.toInt() },
            )
        }
        // Resolver errors carry an execution path and no validation evidence (DGS also puts paths on validation errors).
        val executed = parsed.isNotEmpty() && parsed.all { it.evidence.isEmpty() } && (0 until errors!!.length()).all { i ->
            val path = errors.optJSONObject(i)?.optJSONArray("path")
            path != null && path.length() > 0 && path.opt(0) !in setOf("query", "mutation", "subscription")
        }
        return Probe(response.opt("data") is JSONObject || executed, parsed, ranges)
    }
}
