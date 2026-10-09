package inql.graphql

import graphql.language.*
import graphql.parser.Parser
import graphql.parser.ParserEnvironment
import graphql.parser.ParserOptions
import graphql.schema.GraphQLSchema
import graphql.schema.idl.ScalarInfo
import graphql.schema.idl.errors.SchemaProblem
import graphql.util.TraversalControl
import graphql.util.TraverserContext
import graphql.util.TreeTransformerUtil
import inql.utils.isSchemaPlaceholderField

object SchemaSdlMerger {
    data class MergeResult(
        val schema: GQLSchema?,
        val sdl: String,
        val conflicts: List<String>,
        val errors: List<String>,
        val addedTypes: Int,
        val addedFields: Int,
    )

    private val BUILT_IN_DIRECTIVES = setOf(
        "skip", "include", "deprecated", "specifiedBy", "oneOf", "defer", "experimental_disableErrorPropagation",
    )

    fun merge(primary: GraphQLSchema, secondary: GraphQLSchema): MergeResult = Merger().run(primary, secondary)

    private class Merger {
        private val conflicts = mutableListOf<String>()
        private var addedTypes = 0
        private var addedFields = 0

        fun run(primary: GraphQLSchema, secondary: GraphQLSchema): MergeResult {
            val primaryDoc = toDocument(primary)
            val secondaryDoc = renameTypeReferences(toDocument(secondary), rootRenames(primary, secondary))

            val types = unionByName(typeDefinitions(primaryDoc), typeDefinitions(secondaryDoc), { addedTypes++ }, ::mergeType)
                .map(::stripPlaceholders)
            val directives = unionByName(directiveDefinitions(primaryDoc), directiveDefinitions(secondaryDoc))
            val roots = listOfNotNull(
                "query" to primary.queryType.name,
                (primary.mutationType ?: secondary.mutationType)?.let { "mutation" to it.name },
                (primary.subscriptionType ?: secondary.subscriptionType)?.let { "subscription" to it.name },
            )
            val schemaDefinition = SchemaDefinition.newSchemaDefinition().operationTypeDefinitions(
                roots.map { (op, type) -> OperationTypeDefinition(op, TypeName(type)) },
            ).build()

            val document = Document.newDocument().definitions(types + directives + schemaDefinition).build()
            val (schema, errors) = try {
                GQLSchema(document) to emptyList()
            } catch (e: SchemaProblem) {
                null to e.errors.map { it.message }
            } catch (e: Exception) {
                null to listOf(e.message ?: e.toString())
            }
            val sdl = schema?.sdlSchema ?: AstPrinter.printAst(document)
            return MergeResult(schema, sdl, conflicts, errors, addedTypes, addedFields)
        }

        private fun onEntryAdded(entry: NamedNode<*>) {
            if (!isSchemaPlaceholderField(entry.name)) addedFields++
        }

        private fun mergeType(p: TypeDefinition<*>, s: TypeDefinition<*>): TypeDefinition<*> {
            if (p.javaClass != s.javaClass) {
                if (isStub(p) && !isStub(s)) return s
                if (!isStub(s)) conflicts += "Type ${p.name}: kept ${kindOf(p)}, dropped ${kindOf(s)}"
                return p
            }
            return when (p) {
                is ObjectTypeDefinition -> mergeObject(p, s as ObjectTypeDefinition)
                is InterfaceTypeDefinition -> mergeInterface(p, s as InterfaceTypeDefinition)
                is InputObjectTypeDefinition -> mergeInputObject(p, s as InputObjectTypeDefinition)
                is EnumTypeDefinition -> mergeEnum(p, s as EnumTypeDefinition)
                is UnionTypeDefinition -> mergeUnion(p, s as UnionTypeDefinition)
                else -> p
            }
        }

        private fun mergeObject(p: ObjectTypeDefinition, s: ObjectTypeDefinition) = p.transform {
            it.fieldDefinitions(mergeFields(p.name, p.fieldDefinitions, s.fieldDefinitions))
                .implementz(unionTypeNames(p.implements, s.implements))
                .description(p.description ?: s.description)
                .directives(p.directives.ifEmpty { s.directives })
        }

        private fun mergeInterface(p: InterfaceTypeDefinition, s: InterfaceTypeDefinition) = p.transform {
            it.definitions(mergeFields(p.name, p.fieldDefinitions, s.fieldDefinitions))
                .implementz(unionTypeNames(p.implements, s.implements))
                .description(p.description ?: s.description)
                .directives(p.directives.ifEmpty { s.directives })
        }

        private fun mergeInputObject(p: InputObjectTypeDefinition, s: InputObjectTypeDefinition) = p.transform {
            it.inputValueDefinitions(mergeInputValues(p.name, p.inputValueDefinitions, s.inputValueDefinitions, ::onEntryAdded))
                .description(p.description ?: s.description)
                .directives(p.directives.ifEmpty { s.directives })
        }

        private fun mergeEnum(p: EnumTypeDefinition, s: EnumTypeDefinition) = p.transform {
            it.enumValueDefinitions(unionByName(p.enumValueDefinitions, s.enumValueDefinitions, ::onEntryAdded))
                .description(p.description ?: s.description)
                .directives(p.directives.ifEmpty { s.directives })
        }

        private fun mergeUnion(p: UnionTypeDefinition, s: UnionTypeDefinition) = p.transform {
            it.memberTypes(unionTypeNames(p.memberTypes, s.memberTypes) { addedFields++ })
                .description(p.description ?: s.description)
                .directives(p.directives.ifEmpty { s.directives })
        }

        private fun mergeFields(owner: String, p: List<FieldDefinition>, s: List<FieldDefinition>) =
            unionByName(p, s, ::onEntryAdded) { pf, sf ->
                val path = "$owner.${pf.name}"
                checkTypeConflict(path, pf.type, sf.type)
                pf.transform { it.inputValueDefinitions(mergeInputValues(path, pf.inputValueDefinitions, sf.inputValueDefinitions)) }
            }

        private fun mergeInputValues(
            owner: String,
            p: List<InputValueDefinition>,
            s: List<InputValueDefinition>,
            onAdded: (InputValueDefinition) -> Unit = {},
        ) = unionByName(p, s, onAdded) { pv, sv ->
            checkTypeConflict("$owner.${pv.name}", pv.type, sv.type)
            pv
        }

        private fun checkTypeConflict(path: String, kept: Type<*>, dropped: Type<*>) {
            val keptStr = AstPrinter.printAst(kept)
            val droppedStr = AstPrinter.printAst(dropped)
            if (keptStr != droppedStr) conflicts += "$path: kept `$keptStr`, dropped `$droppedStr`"
        }
    }

    private fun <T : NamedNode<*>> unionByName(
        primary: List<T>,
        secondary: List<T>,
        onAdded: (T) -> Unit = {},
        onBoth: (T, T) -> T = { p, _ -> p },
    ): List<T> {
        val secondaryByName = secondary.associateBy { it.name }
        val primaryNames = primary.mapTo(HashSet()) { it.name }
        return primary.map { p -> secondaryByName[p.name]?.let { onBoth(p, it) } ?: p } +
            secondary.filter { it.name !in primaryNames }.onEach(onAdded)
    }

    private fun unionTypeNames(primary: List<Type<*>>, secondary: List<Type<*>>, onAdded: (TypeName) -> Unit = {}): List<Type<*>> =
        unionByName(primary.filterIsInstance<TypeName>(), secondary.filterIsInstance<TypeName>(), onAdded)

    private fun toDocument(schema: GraphQLSchema): Document =
        Parser.parse(
            ParserEnvironment.newParserEnvironment()
                .document(GraphQLSchemaToSDL.schemaToSDL(schema))
                .parserOptions(ParserOptions.getDefaultSdlParserOptions())
                .build(),
        )

    private fun typeDefinitions(doc: Document): List<TypeDefinition<*>> =
        doc.getDefinitionsOfType(TypeDefinition::class.java)
            .filterNot { ScalarInfo.isGraphqlSpecifiedScalar(it.name) || it.name.startsWith("__") }

    private fun directiveDefinitions(doc: Document): List<DirectiveDefinition> =
        doc.getDefinitionsOfType(DirectiveDefinition::class.java).filterNot { it.name in BUILT_IN_DIRECTIVES }

    private fun rootRenames(primary: GraphQLSchema, secondary: GraphQLSchema): Map<String, String> = listOfNotNull(
        secondary.queryType.name to primary.queryType.name,
        secondary.mutationType?.let { s -> primary.mutationType?.let { s.name to it.name } },
        secondary.subscriptionType?.let { s -> primary.subscriptionType?.let { s.name to it.name } },
    ).filter { (from, to) -> from != to }.toMap()

    private fun renameTypeReferences(doc: Document, renames: Map<String, String>): Document {
        if (renames.isEmpty()) return doc
        val visitor = object : NodeVisitorStub() {
            override fun visitTypeName(node: TypeName, context: TraverserContext<Node<*>>): TraversalControl {
                val target = renames[node.name] ?: return TraversalControl.CONTINUE
                return TreeTransformerUtil.changeNode(context, node.transform { it.name(target) })
            }

            override fun visitObjectTypeDefinition(
                node: ObjectTypeDefinition,
                context: TraverserContext<Node<*>>,
            ): TraversalControl {
                val target = renames[node.name] ?: return TraversalControl.CONTINUE
                return TreeTransformerUtil.changeNode(context, node.transform { it.name(target) })
            }
        }
        return AstTransformer().transform(doc, visitor) as Document
    }

    private fun entryNames(type: TypeDefinition<*>): List<String> = when (type) {
        is ObjectTypeDefinition -> type.fieldDefinitions.map { it.name }
        is InterfaceTypeDefinition -> type.fieldDefinitions.map { it.name }
        is InputObjectTypeDefinition -> type.inputValueDefinitions.map { it.name }
        is EnumTypeDefinition -> type.enumValueDefinitions.map { it.name }
        else -> emptyList()
    }

    private fun isStub(type: TypeDefinition<*>): Boolean =
        type is ScalarTypeDefinition || entryNames(type).let { it.isNotEmpty() && it.all(::isSchemaPlaceholderField) }

    private fun kindOf(type: TypeDefinition<*>) = type.javaClass.simpleName.removeSuffix("TypeDefinition").uppercase()

    private fun stripPlaceholders(type: TypeDefinition<*>): TypeDefinition<*> = when (type) {
        is ObjectTypeDefinition -> type.transform { it.fieldDefinitions(withoutPlaceholders(type.fieldDefinitions)) }
        is InterfaceTypeDefinition -> type.transform { it.definitions(withoutPlaceholders(type.fieldDefinitions)) }
        is InputObjectTypeDefinition -> type.transform { it.inputValueDefinitions(withoutPlaceholders(type.inputValueDefinitions)) }
        is EnumTypeDefinition -> type.transform { it.enumValueDefinitions(withoutPlaceholders(type.enumValueDefinitions)) }
        else -> type
    }

    private fun <T : NamedNode<*>> withoutPlaceholders(items: List<T>): List<T> =
        items.filterNot { isSchemaPlaceholderField(it.name) }.ifEmpty { items }
}
