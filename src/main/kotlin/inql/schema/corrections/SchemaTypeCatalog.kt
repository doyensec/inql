package inql.schema.corrections

import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInputObjectType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLSchema
import graphql.schema.GraphQLUnionType
import inql.scanner.ScanResult

/**
 * User-defined types extracted from a reconstructed schema for correction UI pickers.
 */
object SchemaTypeCatalog {
    val sectionHeaders = setOf(
        "Input types",
        "Enum types",
        "Object types",
        "Union types",
        "Scalar types",
    )

    data class EnumTypeInfo(
        val name: String,
        val values: List<String>,
    )

    data class Catalog(
        val inputTypes: List<String>,
        val inputTypeFields: Map<String, List<String>>,
        val operationRootTypes: List<String>,
        val outputTypes: List<String>,
        val outputTypeFields: Map<String, List<String>>,
        val fieldArguments: Map<String, Map<String, List<String>>>,
        val enumTypes: List<EnumTypeInfo>,
        val scalarTypes: List<String>,
        val unionTypes: List<String>,
    ) {
        val argumentParentTypes: List<String>
            get() = (operationRootTypes + outputTypes).distinct().sorted()
        val allUserTypes: List<String>
            get() = (inputTypes + outputTypes + enumTypes.map { it.name } + scalarTypes + unionTypes)
                .distinct()
                .sorted()

        val renameSourceTypes: List<String>
            get() = allUserTypes

        val renameTargetTypes: List<String>
            get() = (inputTypes + enumTypes.map { it.name } + outputTypes)
                .distinct()
                .sorted()

        fun outputFieldsFor(outputTypeName: String): List<String> {
            return outputTypeFields[outputTypeName].orEmpty()
        }

        fun argumentsFor(parentType: String, fieldName: String): List<String> {
            return fieldArguments[parentType]?.get(fieldName).orEmpty()
        }

        fun argumentTypeOptions(extraTypes: Collection<String> = emptyList()): List<String> {
            return (enumTypes.map { it.name } + inputTypes + scalarTypes + listOf("String", "Int", "Float", "Boolean", "ID") + extraTypes)
                .mapNotNull { GraphQLErrorPathParser.normalizeTypeName(it) ?: it.trim().takeIf { name -> name.isNotEmpty() } }
                .distinct()
                .sorted()
        }

        fun isSectionHeader(label: String): Boolean {
            return label in sectionHeaders
        }

        fun isSpacer(label: String): Boolean {
            return label.isBlank()
        }
    }

    fun fromScanResult(scanResult: ScanResult): Catalog {
        return fromSchema(scanResult.effectiveParsedSchema().schema)
    }

    fun fromSchema(schema: GraphQLSchema): Catalog {
        val builtInScalars = setOf("String", "Int", "Float", "Boolean", "ID")
        val inputTypes = mutableListOf<String>()
        val inputTypeFields = linkedMapOf<String, List<String>>()
        val outputTypes = mutableListOf<String>()
        val outputTypeFields = linkedMapOf<String, List<String>>()
        val fieldArguments = linkedMapOf<String, MutableMap<String, List<String>>>()
        val enumTypes = mutableListOf<EnumTypeInfo>()
        val scalarTypes = mutableListOf<String>()
        val unionTypes = mutableListOf<String>()
        val operationRootTypes = buildList {
            schema.queryType?.name?.let { add(it) }
            schema.mutationType?.name?.let { add(it) }
            schema.subscriptionType?.name?.let { add(it) }
        }

        for ((name, type) in schema.typeMap) {
            if (name.startsWith("__") || name in builtInScalars) continue
            when (type) {
                is GraphQLInputObjectType -> {
                    inputTypes.add(name)
                    val fields = type.fieldDefinitions
                        .map { it.name }
                        .filter { it != "PLACEHOLDER" && it != "_inql_placeholder" }
                        .sorted()
                    if (fields.isNotEmpty()) {
                        inputTypeFields[name] = fields
                    }
                }
                is GraphQLObjectType -> {
                    if (name !in operationRootTypes) {
                        outputTypes.add(name)
                    }
                    registerOutputFields(name, type, outputTypeFields, fieldArguments)
                }
                is GraphQLEnumType -> {
                    val values = type.values
                        .map { it.name }
                        .filter { it != "PLACEHOLDER" && it != "_inql_placeholder" }
                    enumTypes.add(EnumTypeInfo(name, values))
                }
                is GraphQLScalarType -> scalarTypes.add(name)
                is GraphQLUnionType -> unionTypes.add(name)
            }
        }

        return Catalog(
            inputTypes = inputTypes.sorted(),
            inputTypeFields = inputTypeFields.mapValues { (_, fields) -> fields.sorted() },
            operationRootTypes = operationRootTypes,
            outputTypes = outputTypes.sorted(),
            outputTypeFields = outputTypeFields.mapValues { (_, fields) -> fields.sorted() },
            fieldArguments = fieldArguments.mapValues { (_, fields) ->
                fields.mapValues { (_, args) -> args.sorted() }
            },
            enumTypes = enumTypes.sortedBy { it.name },
            scalarTypes = scalarTypes.sorted(),
            unionTypes = unionTypes.sorted(),
        )
    }

    private fun registerOutputFields(
        typeName: String,
        type: GraphQLFieldsContainer,
        outputTypeFields: MutableMap<String, List<String>>,
        fieldArguments: MutableMap<String, MutableMap<String, List<String>>>,
    ) {
        val fields = type.fieldDefinitions
            .map { it.name }
            .filter { it != "PLACEHOLDER" && it != "_inql_placeholder" }
            .sorted()
        if (fields.isNotEmpty()) {
            outputTypeFields[typeName] = fields
        }
        val argsByField = linkedMapOf<String, List<String>>()
        for (field in type.fieldDefinitions) {
            if (field.name == "PLACEHOLDER" || field.name == "_inql_placeholder") continue
            if (field.arguments.isEmpty()) continue
            argsByField[field.name] = field.arguments.map { it.name }.sorted()
        }
        if (argsByField.isNotEmpty()) {
            fieldArguments[typeName] = argsByField
        }
    }

    fun browseListEntries(catalog: Catalog): List<String> {
        val entries = mutableListOf<String>()
        fun addSection(title: String, items: List<String>) {
            if (items.isEmpty()) return
            if (entries.isNotEmpty()) entries.add("")
            entries.add(title)
            entries.addAll(items)
        }
        addSection("Input types", catalog.inputTypes)
        addSection("Enum types", catalog.enumTypes.map { it.name })
        addSection("Object types", catalog.outputTypes)
        addSection("Union types", catalog.unionTypes)
        addSection("Scalar types", catalog.scalarTypes)
        return entries
    }
}
