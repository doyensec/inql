package inql.graphql.scanners

import graphql.language.FieldDefinition
import graphql.language.ListType
import graphql.schema.*
import inql.Logger
import inql.graphql.GQLSchema

class CyclesScanner(private val schema: GQLSchema, private val maxDepth: Int = 100) {
    private val visited = mutableSetOf<Pair<String, String?>>()
    private val visiting = mutableListOf<Pair<String, String?>>()
    private var cycles = mutableListOf<List<Pair<String, String?>>>()

    fun detect() {
        var all = schema.queries + schema.mutations + schema.subscriptions

        for (q in all) {
            detectCycle(q.key, q.value.type )
            visiting.clear()
            visited.clear()
        }

        cycles = cycles.distinct().toMutableList()

    }

    private fun detectCycle(fieldName: String, gqlType: GraphQLType, currentDepth: Int = 0): Boolean {
        if (currentDepth >= maxDepth) {
            Logger.error("Max recursion depth reached ($maxDepth). Might miss some cycles.")
            return false
        }

        // Properly unwrap all type wrappers (non-null, list, etc.)
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
                            val wrappedType = GraphQLTypeUtil.unwrapAll(fieldType.originalWrappedType)
                            if (detectCycle(field.name, wrappedType, currentDepth + 1)) {
                                return true
                            }
                        }

                        fieldType is GraphQLObjectType -> {
                            val nextPair = field.name to fieldType.name
                            if (nextPair !in visited) {
                                if (detectCycle(field.name, fieldType, currentDepth + 1)) {
                                    return true
                                }
                            } else if (nextPair in visiting) {
                                val cycleNodes = visiting.toList() + nextPair
                                cycles.add(cycleNodes)
                                return true
                            }
                        }

                        fieldType is GraphQLTypeReference -> {
                            schema.schema.getType((fieldType as GraphQLTypeReference).name)?.let { resolvedType ->
                                if (detectCycle(field.name, resolvedType, currentDepth + 1)) {
                                    return true
                                }
                            }
                        }
                    }
                }
            }

            is GraphQLList -> {
                // Unwrap list and check its contained type
                val wrappedType = GraphQLTypeUtil.unwrapAll(baseType.originalWrappedType)
                return detectCycle(fieldName, wrappedType, currentDepth)
            }

        }

        visiting.removeLast()
        return false
    }

    private fun cycleAsString(cycle: List<Pair<String, String?>>): String {
        return cycle.joinToString(" -> ") { (field, type) -> "$field ($type)" }
    }

    fun cyclesAsString(): String {
        return cycles.joinToString("\n") { cycleAsString(it) }
    }
}