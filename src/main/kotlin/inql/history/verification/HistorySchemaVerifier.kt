package inql.history.verification

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLSchema
import inql.InQL
import inql.Logger
import inql.bruteforcer.Bruteforcer
import inql.bruteforcer.Bruteforcer.Rejections
import inql.bruteforcer.ErrorEvidence
import inql.graphql.GQLSchema
import inql.graphql.SchemaSdlMerger
import inql.utils.isSchemaPlaceholderField
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

class HistorySchemaVerifier(private val inql: InQL) {
    class VerificationFailedException(message: String) : Exception(message)

    data class Summary(
        val verifiedTypes: Int,
        val verifiedFields: Int,
        val renamedTypes: Map<String, String>,
        val removedFromHistory: Int,
        val keptTypesFromHistory: Int,
        val keptEntriesFromHistory: Int,
        val conflicts: List<String>,
    ) {
        fun describe(): String = buildString {
            appendLine("Proven by the server: $verifiedTypes types, $verifiedFields fields")
            appendLine("History types renamed to the server's names: ${renamedTypes.size}")
            appendLine("History entries removed because the server rejected them: $removedFromHistory")
            appendLine(
                "Kept from history but not verified: $keptTypesFromHistory types, " +
                    "plus $keptEntriesFromHistory fields/arguments/values on verified types",
            )
            append("Conflicts where the verified type replaced the history type: ${conflicts.size}")
        }
    }

    class Outcome(val schema: GQLSchema, val summary: Summary)

    companion object {
        const val UNVERIFIED_NOTE = "InQL: from history, not verified by the server"

        private val rejectionsByContext = ConcurrentHashMap<String, Rejections>()

        private fun contextKey(requestTemplate: HttpRequest, hostKey: String): String {
            val headers = requestTemplate.headers()
                .filterNot { it.name().equals("Content-Length", ignoreCase = true) }
                .map { "${it.name().lowercase()}:${it.value()}" }
                .sorted()
            return "$hostKey#${headers.hashCode()}"
        }

        private fun remember(previous: Rejections?, latest: Rejections, verified: GraphQLSchema): Rejections {
            val result = Rejections()
            previous?.let(result::addAll)
            result.addAll(latest)
            for (type in verified.allTypesAsList) {
                when (type) {
                    is GraphQLFieldsContainer -> {
                        result.remove(Rejections.Kind.FIELD, type.name, type.fieldDefinitions.map { it.name })
                        for (field in type.fieldDefinitions) {
                            result.remove(Rejections.Kind.ARGUMENT, "${type.name}.${field.name}", field.arguments.map { it.name })
                        }
                    }
                    is GraphQLInputObjectType -> result.remove(Rejections.Kind.INPUT_FIELD, type.name, type.fieldDefinitions.map { it.name })
                    is GraphQLEnumType -> result.remove(Rejections.Kind.ENUM_VALUE, type.name, type.values.map { it.name })
                    else -> Unit
                }
            }
            return result
        }
    }

    suspend fun verify(requestTemplate: HttpRequest, hostKey: String, history: GraphQLSchema): Outcome {
        val traffic = withContext(Dispatchers.IO) { HistoryTrafficEvidence.collect(hostKey) }
        Logger.info(
            "History verification: ${traffic.argumentSamples.size} argument samples, " +
                "${traffic.enumCandidates.size} enum candidates and ${traffic.typeNames.size} type names from traffic",
        )
        val context = contextKey(requestTemplate, hostKey)
        val previous = rejectionsByContext[context]
        val names = HistoryNames(history, traffic, previous)
        val verification = Bruteforcer(inql).verify(requestTemplate, names)
        if (!verification.revealed) {
            throw VerificationFailedException(
                "The server did not reveal its schema in validation errors, so nothing could be verified",
            )
        }
        val verified = GQLSchema(verification.sdl).schema
        val rejections = remember(previous, verification.rejections, verified)
        rejectionsByContext[context] = rejections
        val correspondence = SchemaCorrespondence.compute(
            verified,
            history,
            SchemaCorrespondence.Evidence(rejections, traffic.typeNames, names.provenFields(), names.provenArguments()),
        )
        correspondence.ambiguous.forEach { (historyType, candidates) ->
            Logger.info(
                "History verification: $historyType matches several server types ${candidates.sorted()}, " +
                    "renamed to ${correspondence.renames[historyType]}",
            )
        }
        correspondence.renames.forEach { (from, to) -> Logger.info("History verification: renamed $from → $to") }

        val merged = SchemaSdlMerger.merge(
            verified,
            history,
            SchemaSdlMerger.SecondaryAdjustments(
                renames = correspondence.renames,
                removedEntries = correspondence.removedEntries,
                removedArguments = correspondence.removedArguments,
                entryNote = UNVERIFIED_NOTE,
                authoritativeTypes = verification.provenScalars,
            ),
        )
        val schema = merged.schema ?: run {
            Logger.error("Verified schema failed validation:\n${merged.errors.joinToString("\n") { "- $it" }}")
            Logger.debug("Verified SDL:\n${merged.sdl}")
            throw VerificationFailedException("The verified schema failed validation, see the error log for details")
        }
        merged.conflicts.forEach { Logger.info("History verification conflict: $it") }

        val verifiedTypes = verified.allTypesAsList.filter { !it.name.startsWith("__") && !ErrorEvidence.isBuiltInScalar(it.name) }
        val verifiedFields = verifiedTypes.filterIsInstance<GraphQLFieldsContainer>()
            .sumOf { t -> t.fieldDefinitions.count { !isSchemaPlaceholderField(it.name) } }
        return Outcome(
            schema,
            Summary(
                verifiedTypes = verifiedTypes.size,
                verifiedFields = verifiedFields,
                renamedTypes = correspondence.renames,
                removedFromHistory = correspondence.removedCount,
                keptTypesFromHistory = merged.addedTypes,
                keptEntriesFromHistory = merged.addedFields,
                conflicts = merged.conflicts,
            ),
        )
    }
}
