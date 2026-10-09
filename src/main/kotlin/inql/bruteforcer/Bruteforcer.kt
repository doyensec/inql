package inql.bruteforcer

import burp.api.montoya.http.message.requests.HttpRequest
import inql.Config
import inql.InQL
import inql.Logger
import inql.bruteforcer.DiscoveredSchema.Kind
import inql.bruteforcer.DiscoveredSchema.TypeRef
import inql.exceptions.EmptyOrIncorrectWordlistException
import inql.graphql.GQLSchema
import inql.utils.ResourceFileReader
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONObject
import java.io.File
import java.util.Collections

/**
 * Reconstructs a GraphQL schema from validation errors when introspection is disabled.
 *
 * Every schema element must be backed by evidence parsed by [ErrorEvidence]: candidates are probed in buckets,
 * survivors are re-probed until the server stops rejecting any, and every probe carries a sentinel name that the
 * server must reject in a recognised way. Responses that cannot be understood therefore lose discoveries instead of
 * inventing them. Mutation and subscription probes always select an unknown root field so they never execute.
 */
class Bruteforcer(private val inql: InQL) {
    companion object {
        private const val SENTINEL = "____i_n_q_l____"
        private const val ENUM_SENTINEL = "INQL_SENTINEL_VALUE"

        /** Unknown root field that keeps mutation and subscription probes from executing; distinct from [SENTINEL]. */
        private const val NO_EXECUTION_FIELD = "____inql_no_execution____"
        private const val SECOND_SENTINEL = "____i_n_q_l_2____"
        private const val MAX_VERIFY_ROUNDS = 25
        private const val TRUNCATION_THRESHOLD = 50
        private const val MAX_REQUIRED_FILL_ROUNDS = 8
        private val NAME_REGEX = Regex("^[_A-Za-z][_0-9A-Za-z]*$")

        private fun isSchemaName(name: String) = NAME_REGEX.matches(name) && !name.startsWith("__")

        /** Literals sent to learn a value's type; the first six are accepted by custom scalars only. */
        private val VALUE_PROBES = listOf("\"inql\"", "123", "true", "1.5", ENUM_SENTINEL, "{ $SENTINEL: 0 }", "[123]")
    }

    private sealed interface Step {
        data class Field(val parent: String, val name: String) : Step
        data class Fragment(val type: String) : Step
    }

    private class Path(val operation: String, val steps: List<Step>) {
        val depth get() = steps.count { it is Step.Field }
        fun field(parent: String, name: String) = Path(operation, steps + Step.Field(parent, name))
        fun fragment(type: String) = Path(operation, steps + Step.Fragment(type))
    }

    /** Argument [argument] of [parent].[field] at [path], nested inside (input type, input field) levels [nesting]. */
    private class ValueSite(
        val path: Path,
        val parent: String,
        val field: String,
        val selection: String,
        val argument: String,
        val nesting: List<Pair<String, String>>,
    ) {
        fun nested(inputType: String, inputField: String) =
            ValueSite(path, parent, field, selection, argument, nesting + (inputType to inputField))
    }

    /** An error with its location: a column on the one-line query, or the alias index named in Hasura's path. */
    private class ProbeError(val evidence: List<Evidence>, val column: Int?, val alias: Int?) {
        val located get() = column != null || alias != null
    }

    private class Probe(val passed: Boolean, val errors: List<ProbeError>, private val ranges: List<IntRange>) {
        val evidence get() = errors.flatMap { it.evidence }
        fun segmentErrors(i: Int) = errors.filter { (it.column != null && it.column in ranges[i]) || it.alias == i }

        /** True when segment [i] produced no error and every error could be located. */
        fun segmentPassed(i: Int) = passed || (errors.isNotEmpty() && errors.all { it.located } && segmentErrors(i).isEmpty())
    }

    private lateinit var client: ThrottledClient
    private var bucketSize = 64
    private var depthLimit = 2
    private var concurrencyLimit = 8
    private var bruteforceArguments = true
    private var wordlist: List<String> = emptyList()
    private var argumentWordlist: List<String> = emptyList()

    private val schema = DiscoveredSchema()
    private val paths = mutableMapOf<String, Path>()
    private val queue = linkedSetOf<String>()
    private val requiredArguments = mutableMapOf<String, MutableMap<String, String?>>()
    private val scannedValueTypes = mutableSetOf<String>()

    /** Required fields (printed types) of input objects, sent with every object literal of that type. */
    private val requiredInputFields = mutableMapOf<String, MutableMap<String, String>>()
    private val unionSelections = mutableSetOf<String>()
    private val hintedPossibleTypes = mutableMapOf<String, MutableSet<String>>()
    private val discoveredPossibleTypes = mutableMapOf<String, MutableSet<String>>()
    private var leafModifiersPrinted: Boolean? = null
    private var compositeModifiersPrinted: Boolean? = null

    /** The server reports only the first validation error (Hasura), so names are probed sequentially. */
    private var singleError = false

    suspend fun startFromRequest(req: HttpRequest): String {
        val config = Config.getInstance()
        bucketSize = config.getInt("bruteforcer.bucket_size") ?: 64
        depthLimit = config.getInt("bruteforcer.depth_limit") ?: 2
        concurrencyLimit = config.getInt("bruteforcer.concurrency_limit") ?: 8
        bruteforceArguments = config.getBoolean("bruteforcer.bruteforce_arguments") ?: true
        client = ThrottledClient(req)
        wordlist = loadWordlist(config.getString("bruteforcer.custom_wordlist")?.takeIf { it.isNotEmpty() } ?: "wordlist.txt")
        argumentWordlist = loadWordlist(config.getString("bruteforcer.custom_arg_wordlist")?.takeIf { it.isNotEmpty() } ?: "arg_wordlist.txt")

        discover()
        val sdl = schema.toSdl()
        try {
            GQLSchema(sdl)
        } catch (e: Exception) {
            Logger.error("Bruteforcer produced an invalid schema (${e.message}):\n$sdl")
            throw e
        }
        return sdl
    }

    private fun loadWordlist(wordlistFile: String): List<String> {
        val fileContent = when (wordlistFile) {
            "wordlist.txt", "arg_wordlist.txt" -> ResourceFileReader.readFile(wordlistFile)
            else -> File(wordlistFile).takeIf { it.exists() }?.readText()
        } ?: throw EmptyOrIncorrectWordlistException("Wordlist file not found: $wordlistFile")
        if (fileContent.isEmpty()) throw EmptyOrIncorrectWordlistException("$wordlistFile is empty")
        return fileContent.lineSequence().filter(::isSchemaName).distinct().toList()
            .ifEmpty { throw EmptyOrIncorrectWordlistException("No valid words in the $wordlistFile") }
    }

    private suspend fun discover() {
        calibrateModifiers()
        for (operation in listOf("query", "mutation", "subscription")) {
            val root = Path(operation, emptyList())
            // A single unknown root field: some servers allow only one selection in subscriptions.
            val name = probe("$operation { $SENTINEL }").evidence.filterIsInstance<Evidence.UnknownField>()
                .firstOrNull { it.field == SENTINEL }?.parentType ?: continue
            when (operation) {
                "query" -> schema.queryType = name
                "mutation" -> schema.mutationType = name
                else -> schema.subscriptionType = name
            }
            schema.type(name).kind = Kind.OBJECT
            registerComposite(name, root)
        }
        if (schema.queryType == null) {
            Logger.warning("Bruteforcer: the server did not reveal its query type, nothing can be discovered")
            schema.queryType = "Query"
            schema.type("Query").apply { kind = Kind.OBJECT; notes += "the server did not reveal its schema" }
            return
        }
        while (queue.isNotEmpty()) {
            val name = queue.minBy { paths.getValue(it).depth }
            queue.remove(name)
            val path = paths.getValue(name)
            if (path.depth > depthLimit) {
                schema.type(name).notes += "not scanned because of the depth limit"
                continue
            }
            scanComposite(name, path)
        }
        classifyComposites()
    }

    /** `__typename` is `String!` and `__schema` is `__Schema!`: servers printing them bare strip type modifiers. */
    private suspend fun calibrateModifiers() {
        probe("query { __typename { $SENTINEL } }").evidence.filterIsInstance<Evidence.LeafSelection>()
            .firstOrNull { it.field == "__typename" && it.type != null }?.let { leafModifiersPrinted = it.type!!.endsWith("!") }
        probe("query { __schema }").evidence.filterIsInstance<Evidence.MissingSelection>()
            .firstOrNull { it.field == "__schema" }?.let { compositeModifiersPrinted = it.type.endsWith("!") }
        singleError = probe("query { $SENTINEL $SECOND_SENTINEL }").evidence.filterIsInstance<Evidence.UnknownField>().size == 1
    }

    private fun registerComposite(name: String, path: Path) {
        if (ErrorEvidence.isBuiltInScalar(name) || !isSchemaName(name)) return
        val known = paths[name]
        if (known == null) queue += name
        if (known == null || path.depth < known.depth) paths[name] = path
    }

    private suspend fun scanComposite(typeName: String, path: Path) {
        Logger.debug("Bruteforcer: scanning $typeName")
        val type = schema.type(typeName)
        resolveFieldTypes(typeName, path, discoverFieldNames(typeName, path))
        if (type.fields.isEmpty() && path.steps.isNotEmpty()) discoverPossibleTypes(typeName, path)
        for (field in type.fields.values.toList()) discoverArguments(typeName, path, field)
    }

    private suspend fun discoverFieldNames(typeName: String, path: Path): Set<String> {
        fun unknownFields(p: Probe) = p.evidence.filterIsInstance<Evidence.UnknownField>().filter { it.parentType == typeName }
        return discoverNames(
            wordlist,
            send = { names -> probe(wrap(path, names.joinToString(" "))) },
            rejected = { p, _ -> unknownFields(p).map { it.field } },
            observe = { p ->
                if (p.evidence.any { it is Evidence.UnionSelection && it.type == typeName }) unionSelections += typeName
                unknownFields(p).flatMap { it.possibleTypes }.filter(::isSchemaName).forEach {
                    hintedPossibleTypes.getOrPut(typeName) { linkedSetOf() } += it
                    registerComposite(it, path.fragment(it))
                }
                unknownFields(p).flatMap { it.suggestions }
            },
        )
    }

    /** Types fields from "missing selection" and "leaf selection" errors; fields without such evidence are dropped. */
    private suspend fun resolveFieldTypes(typeName: String, path: Path, names: Set<String>) {
        val composite = mutableMapOf<String, String>()
        val leaf = mutableMapOf<String, Evidence.LeafSelection>()
        for (chunk in names.chunked(bucketSize)) {
            probe(wrap(path, chunk.joinToString(" "))).evidence.forEach { e ->
                if (e is Evidence.MissingSelection && e.field in chunk) composite[e.field] = e.type
                if (e is Evidence.MissingArguments && e.field in chunk) {
                    e.arguments.forEach { requiredArguments.getOrPut("$typeName.${e.field}") { linkedMapOf() }[it] = e.type }
                }
            }
            val rest = chunk.filter { it !in composite }
            if (rest.isNotEmpty()) {
                probe(wrap(path, rest.joinToString(" ") { "$it { $SENTINEL }" })).evidence
                    .filterIsInstance<Evidence.LeafSelection>().filter { it.field in rest }.forEach { leaf[it.field] = it }
            }
        }
        for (name in names.filter { it !in composite && it !in leaf }) {
            val evidence = probe(wrap(path, "$name { $SENTINEL }")).evidence
            val leafSelection = evidence.filterIsInstance<Evidence.LeafSelection>().firstOrNull { it.field == name }
            val selectedType = evidence.filterIsInstance<Evidence.UnknownField>().singleOrNull { it.field == SENTINEL }?.parentType
                ?: evidence.filterIsInstance<Evidence.UnionSelection>().singleOrNull()?.type
            if (leafSelection != null) leaf[name] = leafSelection
            else if (selectedType != null) composite[name] = selectedType
        }

        val type = schema.type(typeName)
        for (name in names) {
            val fieldType = when (name) {
                in composite -> typeRef(composite.getValue(name), compositeModifiersPrinted).also {
                    if (it.printed.any { c -> c in "[!" }) compositeModifiersPrinted = true
                    registerComposite(it.named, path.field(typeName, name))
                }
                in leaf -> leaf.getValue(name).type?.let { printed -> typeRef(printed, leafModifiersPrinted) }?.also {
                    if (it.printed.any { c -> c in "[!" }) leafModifiersPrinted = true
                    if (!ErrorEvidence.isBuiltInScalar(it.named)) {
                        schema.type(it.named).apply { this.leaf = true; if (leaf.getValue(name).isEnum) kind = Kind.ENUM }
                    }
                }
                else -> null
            }
            if (fieldType == null) {
                Logger.info("Bruteforcer: dropping $typeName.$name, its type could not be determined")
                continue
            }
            type.fields[name] = DiscoveredSchema.Field(name, fieldType)
        }
    }

    /**
     * Classifies composite types once all are known. A fragment on K is accepted inside T exactly when their possible
     * types overlap, and distinct object types never overlap, so a type overlapping two mutually exclusive types is
     * abstract. Union members and interface implementations are the overlapping object types.
     */
    private suspend fun classifyComposites() {
        val composites = paths.keys.toList()
        val accepted = mutableMapOf<String, Set<String>>()
        for (typeName in composites) {
            val others = composites - typeName
            if (others.isEmpty()) continue
            val fragments = others + SENTINEL
            val p = probeSegments(paths.getValue(typeName), fragments.map { "... on $it { __typename }" })
            val rejected = rejectedFragments(p, typeName, fragments)
            // Spread validation is only trusted when unknown types and the query root are rejected.
            if (SENTINEL !in rejected || (schema.queryType in others && schema.queryType !in rejected)) continue
            accepted[typeName] = others.filter { it !in rejected }.toSet()
        }
        fun overlap(a: String, b: String) = b in accepted[a].orEmpty() && (accepted[b] == null || a in accepted.getValue(b))

        val abstract = composites.filter { t ->
            val neighbours = composites.filter { overlap(t, it) }
            t in unionSelections || hintedPossibleTypes[t].orEmpty().isNotEmpty() ||
                neighbours.any { a -> neighbours.any { b -> a != b && !overlap(a, b) } } ||
                (neighbours.isNotEmpty() && schema.type(t).fields.isEmpty())
        }.toMutableSet()
        // Two overlapping types cannot both be objects: an interface's fields are a subset of its implementation's.
        for (a in composites) for (b in composites) {
            if (a >= b || !overlap(a, b) || a in abstract || b in abstract) continue
            val fa = schema.type(a).fields.keys
            val fb = schema.type(b).fields.keys
            when {
                fa.isNotEmpty() && fb.containsAll(fa) && fa != fb -> abstract += a
                fb.isNotEmpty() && fa.containsAll(fb) && fa != fb -> abstract += b
                else -> {
                    schema.type(a).notes += "overlaps with $b, so one of them is an interface"
                    schema.type(b).notes += "overlaps with $a, so one of them is an interface"
                }
            }
        }

        for (typeName in composites) {
            val type = schema.type(typeName)
            if (typeName in listOfNotNull(schema.queryType, schema.mutationType, schema.subscriptionType)) continue
            val isAbstract = typeName in abstract
            type.kind = when {
                typeName in unionSelections -> Kind.UNION
                isAbstract && type.fields.isNotEmpty() -> Kind.INTERFACE
                isAbstract -> Kind.UNION.also { type.notes += "classified as a union because no fields were discovered" }
                type.fields.isNotEmpty() -> Kind.OBJECT
                else -> null
            }
        }
        for (typeName in abstract) {
            val members = composites.filter { overlap(typeName, it) } + hintedPossibleTypes[typeName].orEmpty() + discoveredPossibleTypes[typeName].orEmpty()
            schema.type(typeName).possibleTypes += members.filter { schema.types[it]?.kind == Kind.OBJECT }
        }
    }

    private suspend fun discoverPossibleTypes(typeName: String, path: Path) {
        val members = discoverNames(
            wordlist,
            send = { names -> probeSegments(path, names.map { "... on $it { __typename }" }) },
            rejected = { p, names -> rejectedFragments(p, typeName, names) },
            observe = { p -> p.evidence.filterIsInstance<Evidence.UnknownType>().flatMap { it.suggestions } },
        )
        for (member in members) {
            discoveredPossibleTypes.getOrPut(typeName) { linkedSetOf() } += member
            registerComposite(member, path.fragment(member))
        }
    }

    /** Fragment conditions in [names] that the server rejected inside [parentType], by name or by error location. */
    private fun rejectedFragments(p: Probe, parentType: String, names: List<String>): Set<String> {
        val byName = p.evidence.mapNotNull {
            when (it) {
                is Evidence.UnknownType -> it.type
                is Evidence.NonCompositeFragment -> it.type
                is Evidence.InvalidSpread -> it.fragmentType.takeIf { _ -> it.parentType == parentType }
                else -> null
            }
        }
        val bySegment = names.filterIndexed { i, _ -> p.segmentErrors(i).isNotEmpty() }
        return (byName + bySegment).toSet()
    }

    private suspend fun discoverArguments(typeName: String, path: Path, field: DiscoveredSchema.Field) {
        val selection = if (field.type.named in paths) "{ __typename }" else ""
        val required = requiredArguments["$typeName.${field.name}"].orEmpty()
        fun unknownArguments(p: Probe) = p.evidence.filterIsInstance<Evidence.UnknownArgument>().filter { it.field == null || it.field == field.name }

        val names = linkedSetOf<String>()
        names += required.keys.filter(::isSchemaName)
        if (bruteforceArguments) {
            names += discoverNames(
                argumentWordlist,
                send = { args -> probe(wrap(path, "${field.name}(${args.joinToString(", ") { "$it: 0" }}) $selection")) },
                rejected = { p, _ -> unknownArguments(p).map { it.argument } },
                observe = { p -> unknownArguments(p).flatMap { it.suggestions } },
            )
        }
        for (argument in names) {
            val site = ValueSite(path, typeName, field.name, selection, argument, emptyList())
            val type = resolveValueType(site, if (argument in required) required[argument] ?: "" else null)
            if (type == null) {
                Logger.info("Bruteforcer: dropping argument $typeName.${field.name}($argument), its type could not be determined")
                continue
            }
            field.args[argument] = DiscoveredSchema.InputValue(argument, type)
            scanValueType(type.named, site)
            field.args[argument] = DiscoveredSchema.InputValue(argument, refineModifiers(site, type))
        }
    }

    /**
     * Learns the type accepted at [site] by sending several literals, each in its own aliased copy of the field.
     * [requiredType] is null for optional values, "" for required values of unknown type, else the printed type.
     */
    private suspend fun resolveValueType(site: ValueSite, requiredType: String?): TypeRef? {
        val target = site.nesting.lastOrNull()?.second ?: site.argument
        val literals = VALUE_PROBES.map { literal(site, it) }
        val variableType = variableUsageType(site)

        fun relevant(outcomes: List<Pair<Probe, Int>>) = outcomes.map { it.first }.distinct().flatMap { it.evidence }.filter { e ->
            when (e) {
                is Evidence.WrongValue -> e.argument == null || (site.nesting.isEmpty() && e.argument == site.argument)
                is Evidence.InputFieldValue -> e.field == target
                is Evidence.UnknownInputField -> e.field == SENTINEL
                is Evidence.UnknownEnumValue -> e.value == ENUM_SENTINEL
                else -> false
            }
        }
        fun printedTypes(evidence: List<Evidence>) = evidence.mapNotNull {
            when (it) {
                is Evidence.WrongValue -> it.type
                is Evidence.InputFieldValue -> it.type
                is Evidence.UnknownInputField -> it.inputType
                is Evidence.UnknownEnumValue -> it.enumType
                else -> null
            }
        } + listOfNotNull(requiredType?.takeIf { it.isNotEmpty() }, variableType)
        // Input values can never have output types; async-graphql names the parent type in "required" errors.
        fun named(printed: List<String>) = printed.map(::namedType).filter { it != site.parent && it !in paths }.toSet().singleOrNull()

        val combined = probeValues(site, literals)
        var outcomes = literals.indices.map { combined to it }
        var evidence = relevant(outcomes)
        // Some servers abort or deduplicate validation across aliases; then each literal is sent on its own.
        if (singleError || combined.errors.any { it.evidence.isEmpty() } || named(printedTypes(evidence)) == null) {
            outcomes = literals.map { probeValues(site, listOf(it)) to 0 }
            evidence = relevant(outcomes)
        }
        val printedTypes = printedTypes(evidence)
        val filledInputType = if (named(printedTypes) == null) inputTypeByFillingRequired(site) else null
        val named = filledInputType ?: named(printedTypes) ?: return null

        val type = schema.type(named)
        val inputEvidence = filledInputType != null ||
            evidence.any { it is Evidence.UnknownInputField || (it is Evidence.WrongValue && it.kind == TypeKind.INPUT_OBJECT) }

        // gqlgen reports enum and scalar values with input-object wording, so enum and leaf evidence wins.
        val listedValues = outcomes.map { it.first }.distinct().flatMap { it.evidence }
            .filterIsInstance<Evidence.EnumValues>().filter { it.enumType == named }.flatMap { it.values }
        type.enumValues += listedValues
        val enumEvidence = listedValues.isNotEmpty() ||
            evidence.any { it is Evidence.UnknownEnumValue || (it is Evidence.WrongValue && it.kind == TypeKind.ENUM) }
        when {
            ErrorEvidence.isBuiltInScalar(named) -> Unit
            enumEvidence -> type.kind = Kind.ENUM
            inputEvidence && !type.leaf -> type.kind = Kind.INPUT_OBJECT
            type.kind == null && acceptsLiteral(site, literals, outcomes, combined) -> type.kind = Kind.SCALAR
            type.kind == null -> type.leaf = true
        }

        if (variableType != null && namedType(variableType) == named) return TypeRef(named, variableType, true)
        val required = requiredType != null
        val printed = printedTypes.firstOrNull { namedType(it) == named && it.any { c -> c in "[!" } && (!required || it.endsWith("!")) }
        if (printed != null) return TypeRef(named, printed, true)
        val listElement = evidence.any { it is Evidence.WrongValue && it.listElement }
        val (modifiers, known) = (if (listElement) listElementModifiers(site, named) else listModifiers(site, named)) ?: (named to false)
        return TypeRef(named, modifiers + if (required) "!" else "", known)
    }

    /**
     * Variables of two different types make the server name the expected type, with modifiers, in validation errors
     * ("Variable "$v" of type "Int" used in position expecting type "[String!]""). async-graphql skips this check.
     */
    private suspend fun variableUsageType(site: ValueSite): String? {
        val variables = mapOf("inqlBoolean" to "Boolean", "inqlInt" to "Int")
        val probe = probeValues(site, variables.keys.map { literal(site, "\$$it") }, variables)
        return probe.evidence.filterIsInstance<Evidence.VariableMismatch>().filter { it.variable in variables }
            .map { it.expectedType }.toSet().singleOrNull()
    }

    /**
     * Servers reporting one error per argument (async-graphql, graph-gophers) report a missing required field before
     * the unknown sentinel field that names the input type, so required fields are filled in until the name appears.
     */
    private suspend fun inputTypeByFillingRequired(site: ValueSite): String? {
        val filled = linkedMapOf<String, String>()
        repeat(MAX_REQUIRED_FILL_ROUNDS) {
            val fields = filled.mapNotNull { (name, printed) -> valueLiteral(printed)?.let { "$name: $it" } } + "$SENTINEL: 0"
            val evidence = probeValues(site, listOf(literal(site, fields.joinToString(", ", "{ ", " }")))).evidence
            evidence.filterIsInstance<Evidence.UnknownInputField>().firstOrNull { it.field == SENTINEL && it.inputType != null }?.let {
                requiredInputFields.getOrPut(it.inputType!!) { linkedMapOf() }.putAll(filled)
                return it.inputType
            }
            val missing = evidence.filterIsInstance<Evidence.MissingInputFields>()
                .flatMap { m -> m.fields.map { it to m.type } }.filter { (name, type) -> name !in filled && type != null }
            if (missing.isEmpty()) return null
            missing.forEach { (name, type) -> filled[name] = type!! }
        }
        return null
    }

    /** Builds the literal for [value] at [site], with the known required fields of every enclosing input object. */
    private fun literal(site: ValueSite, value: String): String =
        site.nesting.foldRight(value) { (type, name), inner -> objectLiteral(type, "$name: $inner", exclude = name) }

    private fun objectLiteral(type: String, body: String, exclude: String? = null): String {
        val required = requiredInputFields[type].orEmpty().filterKeys { it != exclude }
            .mapNotNull { (name, printed) -> valueLiteral(printed)?.let { "$name: $it" } }
        return (required + listOfNotNull(body.ifEmpty { null })).joinToString(", ", "{ ", " }")
    }

    private fun valueLiteral(printed: String): String? =
        literalFor(namedType(printed))?.let { if (printed.startsWith("[")) "[$it]" else it }

    /**
     * Only custom scalars accept the string, number, boolean, enum or object literals sent for an unknown type.
     * An acceptance seen in the combined probe is confirmed alone, as some servers deduplicate errors across aliases.
     */
    private suspend fun acceptsLiteral(site: ValueSite, literals: List<String>, outcomes: List<Pair<Probe, Int>>, combined: Probe): Boolean {
        val index = (0..5).firstOrNull { outcomes[it].first.segmentPassed(outcomes[it].second) } ?: return false
        return outcomes[index].first !== combined || probeValues(site, listOf(literals[index])).segmentPassed(0)
    }

    /**
     * Lists accept a literal wrapped once but not twice (graph-gophers accepts both for any type, which leaves the
     * modifiers unknown). Returns the printed type without the outer non-null modifier and whether it is proven.
     */
    private suspend fun listModifiers(site: ValueSite, named: String): Pair<String, Boolean>? {
        val literal = literalFor(named) ?: return null
        val probe = probeValues(site, listOf(literal, "[$literal]", "[[$literal]]").map { literal(site, it) })
        if (!probe.segmentPassed(0) || probe.errors.any { !it.located }) return null
        fun rejected(i: Int) = probe.segmentErrors(i).any { e -> e.evidence.any { it is Evidence.WrongValue || it is Evidence.InputFieldValue } }
        return when {
            rejected(1) -> named to true
            probe.segmentPassed(1) && rejected(2) -> listElementModifiers(site, named)
            else -> null
        }
    }

    /** Retries list detection once the value type has been scanned and a valid literal for it may be known. */
    private suspend fun refineModifiers(site: ValueSite, type: TypeRef): TypeRef {
        if (type.modifiersKnown) return type
        val (modifiers, known) = listModifiers(site, type.named) ?: return type
        return TypeRef(type.named, modifiers + if (type.printed.endsWith("!")) "!" else "", known)
    }

    /** `[null]` is rejected only by lists of non-null elements; servers without null literals leave it unknown. */
    private suspend fun listElementModifiers(site: ValueSite, named: String): Pair<String, Boolean> {
        val probe = probeValues(site, listOf(literal(site, "[null]")))
        val elementType = probe.segmentErrors(0).flatMap { it.evidence }.firstNotNullOfOrNull {
            when (it) {
                is Evidence.WrongValue -> it.type
                is Evidence.InputFieldValue -> it.type
                else -> null
            }
        }
        return when {
            elementType == "$named!" -> "[$named!]" to true
            probe.segmentPassed(0) -> "[$named]" to true
            else -> "[$named]" to false
        }
    }

    private fun literalFor(named: String): String? = when (named) {
        "String", "ID" -> "\"inql\""
        "Int" -> "1"
        "Float" -> "1.5"
        "Boolean" -> "true"
        else -> schema.types[named]?.let { t ->
            when (t.kind) {
                Kind.ENUM -> t.enumValues.firstOrNull()
                Kind.INPUT_OBJECT -> objectLiteral(t.name, "").takeIf { t.inputFields.isNotEmpty() }
                else -> null
            }
        }
    }

    /** Scans the input fields of an input object, or the values of an enum, reachable through [site]. */
    private suspend fun scanValueType(named: String, site: ValueSite) {
        val type = schema.types[named] ?: return
        if (!scannedValueTypes.add(named)) return
        when {
            type.kind == Kind.INPUT_OBJECT -> scanInputObject(type, site)
            type.kind == Kind.ENUM || (type.kind == null && type.leaf) -> scanEnum(type, site)
        }
    }

    private suspend fun scanInputObject(type: DiscoveredSchema.Type, site: ValueSite) {
        // Fields already known to be required are sent with every probe, so the server will not report them again.
        val required = requiredInputFields[type.name].orEmpty().toMutableMap<String, String?>()
        fun relevant(inputType: String?) = inputType == null || inputType == type.name

        val names = discoverNames(
            wordlist,
            send = { fields -> probeValues(site, fields.map { literal(site, objectLiteral(type.name, "$it: 0", exclude = it)) }) },
            rejected = { p, _ -> p.evidence.filterIsInstance<Evidence.UnknownInputField>().filter { relevant(it.inputType) }.map { it.field } },
            observe = { p ->
                p.evidence.filterIsInstance<Evidence.MissingInputFields>().filter { relevant(it.inputType) }.forEach { m ->
                    m.fields.forEach { field ->
                        required[field] = m.type
                        m.type?.let { requiredInputFields.getOrPut(type.name) { linkedMapOf() }.putIfAbsent(field, it) }
                    }
                }
                p.evidence.filterIsInstance<Evidence.UnknownInputField>().filter { relevant(it.inputType) }.flatMap { it.suggestions } + required.keys
            },
        )
        for (name in names) {
            val fieldType = resolveValueType(site.nested(type.name, name), if (name in required) required[name] ?: "" else null)
            if (fieldType == null) {
                Logger.info("Bruteforcer: dropping input field ${type.name}.$name, its type could not be determined")
                continue
            }
            type.inputFields[name] = DiscoveredSchema.InputValue(name, fieldType)
            if (fieldType.printed.endsWith("!")) requiredInputFields.getOrPut(type.name) { linkedMapOf() }[name] = fieldType.printed
            scanValueType(fieldType.named, site.nested(type.name, name))
            type.inputFields[name] = DiscoveredSchema.InputValue(name, refineModifiers(site.nested(type.name, name), fieldType))
        }
    }

    private suspend fun scanEnum(type: DiscoveredSchema.Type, site: ValueSite) {
        if (type.enumValues.isNotEmpty()) return
        val candidates = (wordlist.map { it.uppercase() } + wordlist).filter { it !in setOf("true", "false", "null") }.distinct()
        val values = discoverNames(
            candidates,
            sentinel = ENUM_SENTINEL,
            send = { values -> probeValues(site, values.map { literal(site, it) }) },
            rejected = { p, values ->
                val byValue = p.evidence.mapNotNull {
                    when (it) {
                        is Evidence.UnknownEnumValue -> it.value
                        is Evidence.WrongValue -> it.value
                        else -> null
                    }
                }
                val bySegment = values.filterIndexed { i, _ ->
                    p.segmentErrors(i).any { e -> e.evidence.any { it is Evidence.WrongValue || it is Evidence.UnknownEnumValue } }
                }
                byValue + bySegment
            },
            observe = { p -> p.evidence.filterIsInstance<Evidence.UnknownEnumValue>().flatMap { it.suggestions } },
        )
        if (values.isEmpty()) return
        type.kind = Kind.ENUM
        type.enumValues += values
    }

    /**
     * Keeps the [candidates] the server does not reject. A probe only counts when the server rejected the [sentinel],
     * and survivors are re-probed until the server stops rejecting any of them. [observe] sees every response and
     * returns suggested names, which are verified like the other candidates.
     */
    private suspend fun discoverNames(
        candidates: List<String>,
        send: suspend (List<String>) -> Probe,
        rejected: (Probe, List<String>) -> Collection<String>,
        observe: (Probe) -> Collection<String> = { emptyList() },
        sentinel: String = SENTINEL,
    ): Set<String> = if (singleError) discoverNamesSequentially(candidates, send, rejected, observe, sentinel) else coroutineScope {
        val semaphore = Semaphore(concurrencyLimit)
        val rejectedAll = Collections.synchronizedSet(mutableSetOf<String>())

        suspend fun round(names: List<String>): Set<String>? {
            val probed = names + sentinel
            val p = send(probed)
            val suggested = observe(p)
            val rejectedNames = rejected(p, probed).toSet()
            if (sentinel !in rejectedNames) {
                // Servers cap the number of reported errors (graphql-js stops at 100); retry truncated probes in halves.
                if (names.size < 2 || p.errors.size < TRUNCATION_THRESHOLD) return null
                val halves = names.chunked((names.size + 1) / 2).map { round(it) }
                return if (halves.any { it == null }) null else halves.filterNotNull().flatten().toSet()
            }
            rejectedAll += rejectedNames
            return (names.toSet() - rejectedNames) + suggested.filter { isSchemaName(it) && it !in rejectedAll }
        }

        var current = candidates.filter(::isSchemaName).chunked(bucketSize)
            .map { bucket -> async { semaphore.withPermit { round(bucket) } } }.awaitAll()
            .filterNotNull().flatten().toSet()
        repeat(MAX_VERIFY_ROUNDS) {
            if (current.isEmpty()) return@coroutineScope current
            val next = current.chunked(bucketSize).map { round(it) ?: return@coroutineScope emptySet() }.flatten().toSet()
            if (next == current) return@coroutineScope current
            current = next
        }
        emptySet()
    }

    /**
     * For servers that report only the first error in document order: every candidate before the reported one passed
     * validation, and the reported one is either rejected or proven by a different error (e.g. a missing selection).
     */
    private suspend fun discoverNamesSequentially(
        candidates: List<String>,
        send: suspend (List<String>) -> Probe,
        rejected: (Probe, List<String>) -> Collection<String>,
        observe: (Probe) -> Collection<String>,
        sentinel: String,
    ): Set<String> {
        val accepted = linkedSetOf<String>()
        val tried = mutableSetOf<String>()
        val pending = ArrayDeque(candidates.filter(::isSchemaName))
        while (pending.isNotEmpty()) {
            val names = pending.take(bucketSize)
            val probed = names + sentinel
            val p = send(probed)
            observe(p).filter { isSchemaName(it) && it !in tried && it !in pending }.forEach { pending.addLast(it) }
            val rejectedNames = rejected(p, probed).toSet()
            val mentioned = p.evidence.flatMap(ErrorEvidence::mentions).toSet()
            val first = probed.indices.firstOrNull { i -> probed[i] in rejectedNames || probed[i] in mentioned || p.segmentErrors(i).isNotEmpty() }
                ?: return accepted
            if (p.errors.size != 1) return emptySet()
            accepted += probed.take(first)
            if (probed[first] != sentinel && probed[first] !in rejectedNames) accepted += probed[first]
            repeat(minOf(first + 1, names.size)) { tried += pending.removeFirst() }
        }
        return accepted - sentinel
    }

    /** Sends each of [values] for [site] in its own aliased copy of the field. */
    private suspend fun probeValues(site: ValueSite, values: List<String>, variables: Map<String, String> = emptyMap()): Probe {
        val otherArguments = requiredLiterals(site.parent, site.field) - site.argument
        val segments = values.mapIndexed { i, value ->
            val args = otherArguments + (site.argument to value)
            "inql$i: ${site.field}(${args.entries.joinToString(", ") { "${it.key}: ${it.value}" }}) ${site.selection}"
        }
        return probeSegments(site.path, segments, variables)
    }

    private suspend fun probeSegments(path: Path, segments: List<String>, variables: Map<String, String> = emptyMap()): Probe {
        val (query, ranges) = build(path, segments, variables)
        return probe(query, ranges)
    }

    private fun wrap(path: Path, inner: String): String = build(path, listOf(inner)).first

    /** Builds a one-line query for [segments] at [path] and the 1-based column range of each segment. */
    private fun build(path: Path, segments: List<String>, variables: Map<String, String> = emptyMap()): Pair<String, List<IntRange>> {
        val definitions = if (variables.isEmpty()) "" else variables.entries.joinToString(", ", "(", ")") { "\$${it.key}: ${it.value}" }
        val prefix = StringBuilder("${path.operation}$definitions { ")
        for (step in path.steps) {
            when (step) {
                is Step.Field -> {
                    val args = requiredLiterals(step.parent, step.name)
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

    /** Literal values for the known required arguments of [parent].[field], so probes below it stay valid. */
    private fun requiredLiterals(parent: String, field: String): Map<String, String> {
        val args = schema.types[parent]?.fields?.get(field)?.args ?: return emptyMap()
        return args.values.filter { it.type.printed.endsWith("!") }.mapNotNull { a ->
            literalFor(a.type.named)?.let { a.name to if (a.type.printed.startsWith("[")) "[$it]" else it }
        }.toMap()
    }

    private fun typeRef(printed: String, modifiersPrinted: Boolean?): TypeRef {
        val named = namedType(printed)
        val known = modifiersPrinted == true || printed.any { it in "[!" }
        return TypeRef(named, if (known) printed else named, known)
    }

    private fun namedType(printed: String) = printed.filter { it != '[' && it != ']' && it != '!' }

    private suspend fun probe(query: String, ranges: List<IntRange> = emptyList()): Probe {
        val response = client.send(query)
        val errors = response.optJSONArray("errors")
        val parsed = (0 until (errors?.length() ?: 0)).mapNotNull { i ->
            val error = errors!!.optJSONObject(i) ?: return@mapNotNull null
            val location = error.optJSONArray("locations")?.optJSONObject(0)
            val path = error.optJSONObject("extensions")?.optString("path")?.takeIf { it.startsWith("$") }
            ProbeError(
                ErrorEvidence.parse(error.optString("message", ""), path),
                location?.takeIf { it.optInt("line") == 1 }?.optInt("column"),
                path?.let { Regex("""\binql(\d+)\b""").find(it)?.groupValues?.get(1)?.toInt() },
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
