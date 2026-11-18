package inql.graphql.scanners

import graphql.schema.*
import inql.Logger
import inql.graphql.GQLSchema

class CyclesScanner(
    private val schema: GQLSchema,
    private val maxDepth: Int = 100,
    private val maxCycles: Int = 10_000,
) {
    private val visited = mutableSetOf<Pair<String, String?>>()
    private val visiting = mutableListOf<Pair<String, String?>>()
    private var cycles = mutableListOf<RawCycle>()

    private data class RawCycle(
        val operationType: GQLSchema.OperationType,
        val nodes: List<Pair<String, String?>>,
    )

    fun detect() {
        val allQueries = schema.queries.map { (k, v) -> Triple(k, v, GQLSchema.OperationType.QUERY) }
        val allMutations = schema.mutations.map { (k, v) -> Triple(k, v, GQLSchema.OperationType.MUTATION) }
        val allSubs = schema.subscriptions.map { (k, v) -> Triple(k, v, GQLSchema.OperationType.SUBSCRIPTION) }

        for ((name, def, op) in allQueries + allMutations + allSubs) {
            if (cycles.size >= maxCycles) break
            detectCycle(name, def.type, 0, op)
            visiting.clear()
            visited.clear()
        }

        cycles = cycles.distinct().toMutableList()
    }

    private fun detectCycle(
        fieldName: String,
        gqlType: GraphQLType,
        currentDepth: Int = 0,
        operationType: GQLSchema.OperationType,
    ): Boolean {
        if (cycles.size >= maxCycles) {
            return false
        }
        if (currentDepth >= maxDepth) {
            Logger.error("Max recursion depth reached ($maxDepth). Might miss some cycles.")
            return false
        }

        val baseType = GraphQLTypeUtil.unwrapAll(gqlType)
        val typeName = baseType.name

        val typePair = fieldName to typeName

        if (typePair in visited) return false
        visited.add(typePair)
        visiting.add(typePair)

        when (baseType) {
            is GraphQLObjectType -> {
                baseType.fieldDefinitions.forEach { field ->
                    val fieldType = GraphQLTypeUtil.unwrapAll(field.type)

                    when {
                        fieldType is GraphQLList -> {
                            val wrappedType = GraphQLTypeUtil.unwrapAll(fieldType.wrappedType)
                            if (detectCycle(field.name, wrappedType, currentDepth + 1, operationType)) {
                                return true
                            }
                        }

                        fieldType is GraphQLObjectType -> {
                            val nextPair = field.name to fieldType.name
                            if (nextPair !in visited) {
                                if (detectCycle(field.name, fieldType, currentDepth + 1, operationType)) {
                                    return true
                                }
                            } else if (nextPair in visiting) {
                                if (cycles.size >= maxCycles) {
                                    Logger.warning("Maximum number of cycles to record ($maxCycles) reached; stopping.")
                                    return true
                                }
                                val cycleNodes = visiting.toList() + nextPair
                                cycles.add(RawCycle(operationType, cycleNodes))
                                return true
                            }
                        }

                        fieldType is GraphQLTypeReference -> {
                            schema.schema.getType((fieldType as GraphQLTypeReference).name)?.let { resolvedType ->
                                if (detectCycle(field.name, resolvedType, currentDepth + 1, operationType)) {
                                    return true
                                }
                            }
                        }
                    }
                }
            }

            is GraphQLList -> {
                val wrappedType = GraphQLTypeUtil.unwrapAll(baseType.wrappedType)
                return detectCycle(fieldName, wrappedType, currentDepth, operationType)
            }
        }

        visiting.removeLast()
        return false
    }

    fun cycleResults(): List<CycleResult> {
        return cycles.map { raw ->
            val names = raw.nodes.map { it.first }
            val closingPair = raw.nodes.last()
            val repeatStart = raw.nodes.dropLast(1).indexOfFirst { it == closingPair }.let { idx ->
                if (idx < 0) 0 else idx
            }
            CycleResult(
                operationType = raw.operationType,
                pathFieldNames = names,
                cycleRepeatStartIndex = repeatStart,
            )
        }
    }
}
