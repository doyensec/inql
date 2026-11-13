package inql.history.verification

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLInterfaceType
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType
import inql.bruteforcer.Bruteforcer.Rejections
import inql.bruteforcer.ErrorEvidence
import inql.utils.isSchemaPlaceholderField

internal class SchemaCorrespondence(
    val renames: Map<String, String>,
    val removedEntries: Map<String, Set<String>>,
    val removedArguments: Map<String, Set<String>>,
    val ambiguous: Map<String, Set<String>>,
) {
    val removedCount get() = removedEntries.values.sumOf { it.size } + removedArguments.values.sumOf { it.size }

    class Evidence(
        val rejections: Rejections,
        val realTypeNames: Set<String>,
        val provenFields: Map<String, Set<String>>,
        val provenArguments: Map<String, Set<String>>,
    )

    private enum class Kind { OBJECT, INTERFACE, UNION, INPUT, LEAF }

    companion object {
        private const val MIN_ORPHAN_ENTRIES = 2

        fun compute(verified: GraphQLSchema, history: GraphQLSchema, evidence: Evidence): SchemaCorrespondence =
            Walker(verified, history, evidence).run()

        private fun kind(type: GraphQLNamedType): Kind? = when (type) {
            is GraphQLObjectType -> Kind.OBJECT
            is GraphQLInterfaceType -> Kind.INTERFACE
            is GraphQLUnionType -> Kind.UNION
            is GraphQLInputObjectType -> Kind.INPUT
            is GraphQLEnumType, is GraphQLScalarType -> Kind.LEAF
            else -> null
        }
    }

    private class Removals {
        val entries = linkedMapOf<String, MutableSet<String>>()
        val arguments = linkedMapOf<String, MutableSet<String>>()
    }

    private class Walker(
        private val verified: GraphQLSchema,
        private val history: GraphQLSchema,
        private val evidence: Evidence,
    ) {
        private val votes = linkedMapOf<String, MutableMap<String, Int>>()
        private val removalsByPair = linkedMapOf<Pair<String, String>, Removals>()
        private val queue = ArrayDeque<Pair<GraphQLNamedType, GraphQLNamedType>>()
        private val seen = mutableSetOf<Pair<String, String>>()
        private val historyRoots = setOfNotNull(history.queryType?.name, history.mutationType?.name, history.subscriptionType?.name)

        fun run(): SchemaCorrespondence {
            pair(verified.queryType, history.queryType)
            pair(verified.mutationType, history.mutationType)
            pair(verified.subscriptionType, history.subscriptionType)
            for (type in history.allTypesAsList) {
                if (type.name.startsWith("__")) continue
                pair(verified.getType(type.name), type)
            }
            while (queue.isNotEmpty()) {
                val (v, h) = queue.removeFirst()
                visit(v, h)
            }

            val renames = linkedMapOf<String, String>()
            val ambiguous = linkedMapOf<String, Set<String>>()
            for ((historyName, candidates) in votes) {
                if (!renameable(historyName)) continue
                val ranked = candidates.entries.sortedByDescending { it.value }
                if (ranked.size > 1) ambiguous[historyName] = candidates.keys.toSet()
                if (ranked.size > 1 && ranked[0].value == ranked[1].value) continue
                renames[historyName] = ranked[0].key
            }
            while (true) {
                val found = orphanRenames(renames)
                if (found.isEmpty()) break
                renames += found
            }
            val removals = finalRemovals(renames)
            return SchemaCorrespondence(renames, removals.entries, removals.arguments, ambiguous)
        }

        private fun renameable(historyName: String) =
            verified.getType(historyName) == null && historyName !in historyRoots && historyName !in evidence.realTypeNames

        private fun target(historyName: String, renames: Map<String, String>): String? =
            renames[historyName] ?: historyName.takeIf { verified.getType(it) != null }

        private fun finalRemovals(renames: Map<String, String>): Removals {
            val result = Removals()
            for ((pair, removals) in removalsByPair) {
                val (verifiedName, historyName) = pair
                if (historyName !in historyRoots && target(historyName, renames) != verifiedName) continue
                for ((type, names) in removals.entries) {
                    val removable = names - evidence.provenFields[type].orEmpty()
                    if (removable.isNotEmpty()) result.entries.getOrPut(type) { linkedSetOf() } += removable
                }
                for ((field, names) in removals.arguments) {
                    val removable = names - evidence.provenArguments[field].orEmpty()
                    if (removable.isNotEmpty()) result.arguments.getOrPut(field) { linkedSetOf() } += removable
                }
            }
            return result
        }

        private fun orphanRenames(matched: Map<String, String>): Map<String, String> {
            val result = linkedMapOf<String, String>()
            for (h in history.allTypesAsList) {
                if (h.name.startsWith("__") || h.name in matched || h.name in votes || !renameable(h.name)) continue
                val names = entryNames(h).filterNot(::isSchemaPlaceholderField).toSet()
                if (names.size < MIN_ORPHAN_ENTRIES) continue
                val candidates = verified.allTypesAsList.filter { v ->
                    !v.name.startsWith("__") && kind(v) == kind(h) && entryNames(v).containsAll(names) &&
                        names.all { typesAgree(entryType(h, it), entryType(v, it), matched) }
                }
                candidates.singleOrNull()?.let { result[h.name] = it.name }
            }
            return result
        }

        private fun entryType(type: GraphQLNamedType, name: String): GraphQLNamedType? = when (type) {
            is GraphQLFieldsContainer -> type.getFieldDefinition(name)?.type?.let(::namedType)
            is GraphQLInputObjectType -> type.getField(name)?.type?.let(::namedType)
            else -> null
        }

        private fun typesAgree(historyType: GraphQLNamedType?, verifiedType: GraphQLNamedType?, matched: Map<String, String>): Boolean {
            if (historyType == null || verifiedType == null || ErrorEvidence.isBuiltInScalar(historyType.name)) return true
            val expected = target(historyType.name, matched) ?: return true
            return expected == verifiedType.name
        }

        private fun entryNames(type: GraphQLNamedType): List<String> = when (type) {
            is GraphQLFieldsContainer -> type.fieldDefinitions.map { it.name }
            is GraphQLInputObjectType -> type.fieldDefinitions.map { it.name }
            is GraphQLEnumType -> type.values.map { it.name }
            else -> emptyList()
        }

        private fun pair(v: GraphQLType?, h: GraphQLType?) {
            val vn = v?.let(::namedType) ?: return
            val hn = h?.let(::namedType) ?: return
            if (listOf(vn, hn).any { ErrorEvidence.isBuiltInScalar(it.name) || it.name.startsWith("__") }) return
            if (!compatible(vn, hn)) return
            if (seen.add(vn.name to hn.name)) queue += vn to hn
        }

        private fun compatible(v: GraphQLNamedType, h: GraphQLNamedType): Boolean {
            if (kind(v) != null && kind(v) == kind(h)) return true
            return v is GraphQLInterfaceType && h is GraphQLObjectType && renameable(h.name)
        }

        private fun visit(v: GraphQLNamedType, h: GraphQLNamedType) {
            if (h.name !in historyRoots) votes.getOrPut(h.name) { linkedMapOf() }.merge(v.name, 1, Int::plus)
            val removals = if (kind(v) == kind(h)) removalsByPair.getOrPut(v.name to h.name) { Removals() } else null
            when {
                v is GraphQLFieldsContainer && h is GraphQLFieldsContainer -> visitFields(v, h, removals)
                v is GraphQLInputObjectType && h is GraphQLInputObjectType -> visitInputFields(v, h, removals)
                v is GraphQLEnumType && h is GraphQLEnumType -> visitEnumValues(v, h, removals)
            }
            if (h is GraphQLUnionType) {
                for (member in h.types) pair(verified.getType(member.name), member)
            }
        }

        private fun visitFields(v: GraphQLFieldsContainer, h: GraphQLFieldsContainer, removals: Removals?) {
            for (hf in h.fieldDefinitions) {
                if (isSchemaPlaceholderField(hf.name)) continue
                val vf = v.getFieldDefinition(hf.name)
                if (vf == null) {
                    if (hf.name in evidence.rejections.get(Rejections.Kind.FIELD, v.name)) {
                        removals?.entries?.getOrPut(h.name) { linkedSetOf() }?.add(hf.name)
                    }
                    continue
                }
                pair(vf.type, hf.type)
                for (ha in hf.arguments) {
                    val va = vf.getArgument(ha.name)
                    if (va == null) {
                        if (ha.name in evidence.rejections.get(Rejections.Kind.ARGUMENT, "${v.name}.${hf.name}")) {
                            removals?.arguments?.getOrPut("${h.name}.${hf.name}") { linkedSetOf() }?.add(ha.name)
                        }
                        continue
                    }
                    pair(va.type, ha.type)
                }
            }
        }

        private fun visitInputFields(v: GraphQLInputObjectType, h: GraphQLInputObjectType, removals: Removals?) {
            for (hf in h.fieldDefinitions) {
                if (isSchemaPlaceholderField(hf.name)) continue
                val vf = v.getField(hf.name)
                if (vf == null) {
                    if (hf.name in evidence.rejections.get(Rejections.Kind.INPUT_FIELD, v.name)) {
                        removals?.entries?.getOrPut(h.name) { linkedSetOf() }?.add(hf.name)
                    }
                    continue
                }
                pair(vf.type, hf.type)
            }
        }

        private fun visitEnumValues(v: GraphQLEnumType, h: GraphQLEnumType, removals: Removals?) {
            for (value in h.values) {
                if (isSchemaPlaceholderField(value.name) || v.getValue(value.name) != null) continue
                if (value.name in evidence.rejections.get(Rejections.Kind.ENUM_VALUE, v.name)) {
                    removals?.entries?.getOrPut(h.name) { linkedSetOf() }?.add(value.name)
                }
            }
        }
    }
}
