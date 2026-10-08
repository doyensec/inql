package inql.attacker

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import graphql.language.AstPrinter
import graphql.language.AstTransformer
import graphql.language.Document
import graphql.language.Field
import graphql.language.FragmentDefinition
import graphql.language.FragmentSpread
import graphql.language.InlineFragment
import graphql.language.Node
import graphql.language.NodeTraverser
import graphql.language.NodeVisitorStub
import graphql.language.OperationDefinition
import graphql.language.Selection
import graphql.language.SelectionSet
import graphql.language.TypeName
import graphql.language.VariableDefinition
import graphql.language.VariableReference
import graphql.parser.Parser
import graphql.util.TraversalControl
import graphql.util.TraverserContext
import graphql.util.TreeTransformerUtil

class AliasBatchException(message: String) : Exception(message)

object AliasBatchRewriter {
    private val parser = Parser()

    fun rewrite(
        query: String,
        operationName: String?,
        selectedVariables: Set<String>,
        combinations: List<Map<String, JsonElement>>,
        baseVariables: JsonObject,
    ): Pair<String, JsonObject> {
        val document = parser.parseDocument(query)
        val operations = document.definitions.filterIsInstance<OperationDefinition>()
        val operation = BatchVariableCollector.selectOperation(operations, operationName)
            ?: throw AliasBatchException("Could not find the GraphQL operation to rewrite.")

        val selectedTopLevel = selectedVariables.map { BatchVariableCollector.graphqlName(it) }.toSet()
        val fragments = document.definitions.filterIsInstance<FragmentDefinition>().associateBy { it.name }

        val originalStillUsed = selectedTopLevel.filter { top ->
            combinations.any { combo ->
                combo.entries.none { !it.value.isJsonNull && BatchVariableCollector.graphqlName(it.key) == top }
            }
        }.toSet()

        val originalSelectionSet = operation.selectionSet
            ?: throw AliasBatchException("The GraphQL operation has no selection set to alias.")
        // Root fragments must be inlined so their fields can be aliased per item, and fragments that use a
        // selected variable must be inlined so each copy can reference its own renamed variable.
        val fragmentInliner = FragmentInliner(fragments, fragmentsUsingVariables(fragments, selectedTopLevel))
        val selectionSet = fragmentInliner.inlineRoot(originalSelectionSet)
        val referencedNames = BatchVariableCollector.collectVariableReferences(selectionSet)
            .plus(operation.directives.flatMap { BatchVariableCollector.collectVariableReferences(it) })
            .ifEmpty { BatchVariableCollector.collectFromQueryText(query).toSet() }
        val originalDefs = operation.variableDefinitions.associateBy { it.name }
        val newDefs = mutableListOf<VariableDefinition>()
        for (def in operation.variableDefinitions) {
            if (def.name !in selectedTopLevel || def.name in originalStillUsed) {
                newDefs.add(def)
            }
        }
        for ((index, overrides) in combinations.withIndex()) {
            for (top in overrideTopLevels(overrides)) {
                if (top !in referencedNames) continue
                val clonedName = suffixedName(top, index)
                val original = originalDefs[top]
                newDefs.add(
                    original?.transform { it.name(clonedName) }
                        ?: VariableDefinition.newVariableDefinition()
                            .name(clonedName)
                            .type(TypeName("String"))
                            .build(),
                )
            }
        }

        val newSelections = mutableListOf<Selection<*>>()
        for ((index, overrides) in combinations.withIndex()) {
            val mapping = overrideTopLevels(overrides)
                .filter { it in referencedNames }
                .associateWith { suffixedName(it, index) }
            val usedAliases = mutableSetOf<String>()
            for (selection in selectionSet.selections) {
                val rewritten = renameVariables(selection, mapping)
                newSelections.add(aliasRootSelection(rewritten, index, usedAliases))
            }
        }
        if (newSelections.isEmpty()) {
            throw AliasBatchException("The GraphQL operation has no fields to alias.")
        }

        val newSelectionSet = SelectionSet.newSelectionSet().selections(newSelections).build()
        val newOperation = operation.transform { builder ->
            builder.variableDefinitions(newDefs)
            builder.selectionSet(newSelectionSet)
        }

        val newDefinitions = document.definitions.map { def ->
            if (def === operation) newOperation else def
        }
        val newDocument = removeFragmentsUnusedAfterInlining(
            original = document,
            rewritten = document.transform { it.definitions(newDefinitions) },
        )

        val newVariables = JsonObject()
        for ((key, value) in baseVariables.entrySet()) {
            if (key !in selectedTopLevel || key in originalStillUsed) {
                newVariables.add(key, value)
            }
        }
        for ((index, overrides) in combinations.withIndex()) {
            val patched = BatchVariableCollector.applyOverrides(baseVariables, overrides)
            for (top in overrideTopLevels(overrides)) {
                patched.get(top)?.let { newVariables.add(suffixedName(top, index), it) }
            }
        }

        return Pair(AstPrinter.printAst(newDocument), newVariables)
    }

    private fun overrideTopLevels(overrides: Map<String, JsonElement>): Set<String> {
        return overrides
            .filter { !it.value.isJsonNull }
            .keys
            .map { BatchVariableCollector.graphqlName(it) }
            .toSet()
    }

    private fun suffixedName(name: String, index: Int): String = "${name}_$index"

    /** Names of fragments that reference any of [variables], directly or through nested fragment spreads. */
    private fun fragmentsUsingVariables(
        fragments: Map<String, FragmentDefinition>,
        variables: Set<String>,
    ): Set<String> {
        val result = mutableSetOf<String>()
        val visiting = mutableSetOf<String>()

        fun uses(name: String): Boolean {
            if (name in result) return true
            val fragment = fragments[name] ?: return false
            if (!visiting.add(name)) return false
            val direct = BatchVariableCollector.collectVariableReferences(fragment).any { it in variables }
            val nested = fragmentSpreadNames(fragment).any { uses(it) }
            visiting.remove(name)
            if (direct || nested) result.add(name)
            return direct || nested
        }

        fragments.keys.forEach { uses(it) }
        return result
    }

    private fun fragmentSpreadNames(node: Node<*>): Set<String> {
        val names = linkedSetOf<String>()
        NodeTraverser().preOrder(
            object : NodeVisitorStub() {
                override fun visitFragmentSpread(
                    node: FragmentSpread,
                    data: TraverserContext<Node<*>>,
                ): TraversalControl {
                    names.add(node.name)
                    return TraversalControl.CONTINUE
                }
            },
            node,
        )
        return names
    }

    /**
     * Drops fragment definitions that were used before the rewrite but no longer are because every spread of
     * them was inlined. GraphQL rejects documents with unused fragments.
     */
    private fun removeFragmentsUnusedAfterInlining(original: Document, rewritten: Document): Document {
        val usedBefore = usedFragmentNames(original)
        val usedAfter = usedFragmentNames(rewritten)
        val obsolete = usedBefore - usedAfter
        if (obsolete.isEmpty()) return rewritten
        return rewritten.transform { builder ->
            builder.definitions(
                rewritten.definitions.filterNot { it is FragmentDefinition && it.name in obsolete },
            )
        }
    }

    /** Fragments reachable from the document's operations. */
    private fun usedFragmentNames(document: Document): Set<String> {
        val fragments = document.definitions.filterIsInstance<FragmentDefinition>().associateBy { it.name }
        val used = mutableSetOf<String>()
        val pending = ArrayDeque(
            document.definitions.filterIsInstance<OperationDefinition>().flatMap { fragmentSpreadNames(it) },
        )
        while (pending.isNotEmpty()) {
            val name = pending.removeFirst()
            if (!used.add(name)) continue
            fragments[name]?.let { pending.addAll(fragmentSpreadNames(it)) }
        }
        return used
    }

    private class FragmentInliner(
        private val fragments: Map<String, FragmentDefinition>,
        private val mustInline: Set<String>,
    ) {
        /** Inlines every fragment spread directly at the root, plus [mustInline] fragments at any depth. */
        fun inlineRoot(selectionSet: SelectionSet): SelectionSet = inlineSet(selectionSet, emptySet(), atRoot = true)

        private fun inlineSet(selectionSet: SelectionSet, stack: Set<String>, atRoot: Boolean): SelectionSet {
            val selections = selectionSet.selections.map { inlineSelection(it, stack, atRoot) }
            return selectionSet.transform { it.selections(selections) }
        }

        private fun inlineSelection(selection: Selection<*>, stack: Set<String>, atRoot: Boolean): Selection<*> {
            return when (selection) {
                is FragmentSpread -> {
                    if (!atRoot && selection.name !in mustInline) return selection
                    val fragment = fragments[selection.name]
                        ?: throw AliasBatchException("Fragment \"${selection.name}\" is not defined in the query.")
                    if (selection.name in stack) {
                        throw AliasBatchException("Fragment \"${selection.name}\" spreads itself.")
                    }
                    InlineFragment.newInlineFragment()
                        .typeCondition(fragment.typeCondition)
                        .directives(selection.directives)
                        .selectionSet(inlineSet(fragment.selectionSet, stack + selection.name, atRoot))
                        .build()
                }
                is InlineFragment -> selection.transform {
                    it.selectionSet(inlineSet(selection.selectionSet, stack, atRoot))
                }
                is Field -> {
                    val children = selection.selectionSet ?: return selection
                    selection.transform { it.selectionSet(inlineSet(children, stack, atRoot = false)) }
                }
                else -> selection
            }
        }
    }

    private fun renameVariables(selection: Selection<*>, mapping: Map<String, String>): Selection<*> {
        if (mapping.isEmpty()) return selection
        val transformed = AstTransformer().transform(selection as Node<*>, RenameVariablesVisitor(mapping))
            ?: return selection
        @Suppress("UNCHECKED_CAST")
        return transformed as Selection<*>
    }

    private fun aliasRootSelection(
        selection: Selection<*>,
        itemIndex: Int,
        usedAliases: MutableSet<String>,
    ): Selection<*> {
        if (selection is InlineFragment) {
            val aliased = selection.selectionSet.selections.map { aliasRootSelection(it, itemIndex, usedAliases) }
            return selection.transform { builder ->
                builder.selectionSet(selection.selectionSet.transform { it.selections(aliased) })
            }
        }
        if (selection !is Field) return selection
        val base = selection.alias ?: selection.name
        val sanitized = base.replace(Regex("[^A-Za-z0-9_]"), "_").ifBlank { "field" }
        var candidate = "op${itemIndex}_$sanitized"
        var n = 2
        while (candidate in usedAliases) {
            candidate = "op${itemIndex}_${sanitized}_$n"
            n++
        }
        usedAliases.add(candidate)
        return selection.transform { it.alias(candidate) }
    }

    private class RenameVariablesVisitor(
        private val mapping: Map<String, String>,
    ) : NodeVisitorStub() {
        override fun visitVariableReference(
            node: VariableReference,
            data: TraverserContext<Node<*>>,
        ): TraversalControl {
            val newName = mapping[node.name] ?: return TraversalControl.CONTINUE
            TreeTransformerUtil.changeNode(data, node.transform { it.name(newName) })
            return TraversalControl.CONTINUE
        }
    }
}
