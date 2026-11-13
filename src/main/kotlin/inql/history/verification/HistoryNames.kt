package inql.history.verification

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLType
import graphql.schema.GraphQLTypeUtil
import graphql.schema.GraphQLUnionType
import inql.bruteforcer.Bruteforcer
import inql.bruteforcer.Bruteforcer.Rejections
import inql.bruteforcer.NameSource
import inql.bruteforcer.Path
import inql.bruteforcer.SampleValue
import inql.bruteforcer.Step
import inql.graphql.RESERVED_LITERALS
import inql.utils.isSchemaPlaceholderField

internal fun namedType(type: GraphQLType): GraphQLNamedType? = GraphQLTypeUtil.unwrapAll(type) as? GraphQLNamedType

internal class HistoryNames(
    private val history: GraphQLSchema,
    private val traffic: HistoryTrafficEvidence,
    private val previouslyRejected: Rejections? = null,
) : NameSource {
    override val scanArguments = true
    override val providesTypeHints = true

    private val namedTypes: List<GraphQLNamedType> = history.allTypesAsList.filter { !it.name.startsWith("__") }
    private val inputTypes = namedTypes.filterIsInstance<GraphQLInputObjectType>()
    private val outputFields = namedTypes.filterIsInstance<GraphQLFieldsContainer>().flatMap { it.fieldDefinitions }

    private val historyArgumentNames = outputFields.flatMap { f -> f.arguments.map { it.name } }.filter(::usable).distinct()
    private val historyInputFieldNames = inputTypes.flatMap { t -> t.fieldDefinitions.map { it.name } }.filter(::usable).distinct()
    private val allNames = (outputFields.map { it.name } + historyArgumentNames + historyInputFieldNames + traffic.valueNames)
        .filter(::usable).distinct()

    private val enumValueNames = (namedTypes.filterIsInstance<GraphQLEnumType>().flatMap { e -> e.values.map { it.name } } + traffic.enumCandidates)
        .filter { usable(it) && it !in RESERVED_LITERALS }.distinct()

    private val objectTypeNames = (namedTypes.filter { it is GraphQLObjectType && !isRoot(it.name) }.map { it.name } + traffic.typeNames)
        .filter(::usable).distinct()

    private val maxTrafficDepth = traffic.selectedFields.keys.maxOfOrNull { key -> key.count { it == '/' } } ?: 0

    override fun fieldNames(typeName: String, path: Path): List<String> {
        val local = traffic.selectedFields[path.key].orEmpty() +
            historyTypes(typeName, path).flatMap { t -> t.fieldDefinitions.map { it.name } }
        return (local + allNames.without(Rejections.Kind.FIELD, typeName)).filter(::usable).distinct()
    }

    override fun argumentNames(typeName: String, path: Path, field: String): List<String> {
        val local = traffic.argumentNames[path.keyWith(field)].orEmpty() +
            historyTypes(typeName, path).flatMap { t -> t.getFieldDefinition(field)?.arguments?.map { it.name }.orEmpty() }
        val borrowed = (historyArgumentNames + historyInputFieldNames + traffic.valueNames).without(Rejections.Kind.ARGUMENT, "$typeName.$field")
        return (local + borrowed).filter(::usable).distinct()
    }

    override fun inputFieldNames(inputType: String): List<String> {
        val local = (history.getType(inputType) as? GraphQLInputObjectType)?.fieldDefinitions?.map { it.name }.orEmpty()
        val borrowed = (historyInputFieldNames + allNames).without(Rejections.Kind.INPUT_FIELD, inputType)
        return (local + borrowed).filter(::usable).distinct()
    }

    override fun enumValues(enumType: String): List<String> {
        val local = (history.getType(enumType) as? GraphQLEnumType)?.values?.map { it.name }.orEmpty()
        return (local + enumValueNames.without(Rejections.Kind.ENUM_VALUE, enumType)).filter(::usable).distinct()
    }

    override fun possibleTypeNames(typeName: String, path: Path): List<String> {
        val local = ((historyTypeAt(path) ?: history.getType(typeName)) as? GraphQLUnionType)?.types?.map { it.name }.orEmpty()
        return (local + objectTypeNames).distinct()
    }

    override fun ignoresDepthLimit(path: Path): Boolean =
        path.key in traffic.selectedFields || (path.depth <= maxTrafficDepth && historyTypeAt(path) != null)

    override fun argumentSamples(path: Path, field: String): Map<String, SampleValue> =
        traffic.argumentSamples[path.keyWith(field)].orEmpty()

    override fun inputFieldTypeHint(inputType: String, field: String): String? =
        (history.getType(inputType) as? GraphQLInputObjectType)?.getField(field)?.type?.let(::namedType)?.name

    override fun typesSeenAt(path: Path): List<String> = traffic.typesAt[path.key].orEmpty().toList()

    /** Fields of each history type that an operation answered with data selected. */
    fun provenFields(): Map<String, Set<String>> {
        val proven = linkedMapOf<String, MutableSet<String>>()
        for ((key, fields) in traffic.acceptedFields) {
            val type = historyTypeAt(key) ?: continue
            proven.getOrPut(type.name) { linkedSetOf() } += fields
        }
        return proven
    }

    /** Arguments, keyed by `HistoryType.field`, that an operation answered with data used. */
    fun provenArguments(): Map<String, Set<String>> {
        val proven = linkedMapOf<String, MutableSet<String>>()
        for ((key, arguments) in traffic.acceptedArguments) {
            val parent = historyTypeAt(key.substringBeforeLast('/')) ?: continue
            proven.getOrPut("${parent.name}.${key.substringAfterLast('/')}") { linkedSetOf() } += arguments
        }
        return proven
    }

    private fun historyTypes(typeName: String, path: Path) =
        listOfNotNull(historyTypeAt(path), history.getType(typeName)).filterIsInstance<GraphQLFieldsContainer>()

    private fun historyTypeAt(key: String): GraphQLNamedType? {
        val parts = key.split('/')
        return historyTypeAt(Path(parts.first(), parts.drop(1).map { Step.Field("", it) }))
    }

    private fun historyTypeAt(path: Path): GraphQLNamedType? {
        var current: GraphQLNamedType = when (path.operation) {
            "mutation" -> history.mutationType
            "subscription" -> history.subscriptionType
            else -> history.queryType
        } ?: return null
        for (step in path.steps) {
            current = when (step) {
                is Step.Field -> {
                    val field = (current as? GraphQLFieldsContainer)?.getFieldDefinition(step.name) ?: return null
                    namedType(field.type) ?: return null
                }
                is Step.Fragment -> history.getType(step.type) as? GraphQLNamedType ?: return null
            }
        }
        return current
    }

    private fun List<String>.without(kind: Rejections.Kind, key: String): List<String> {
        val skip = previouslyRejected?.get(kind, key).orEmpty()
        return if (skip.isEmpty()) this else filterNot { it in skip }
    }

    private fun isRoot(name: String) =
        name == history.queryType?.name || name == history.mutationType?.name || name == history.subscriptionType?.name

    private fun usable(name: String) = Bruteforcer.isSchemaName(name) && !isSchemaPlaceholderField(name)
}
