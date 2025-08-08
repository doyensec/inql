package inql.bruteforcer

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.Scalars
import graphql.Scalars.*
import graphql.schema.*
import graphql.schema.GraphQLTypeUtil.unwrapType
import graphql.schema.idl.RuntimeWiring
import graphql.schema.idl.SchemaGenerator
import graphql.schema.idl.SchemaParser
import graphql.schema.idl.SchemaPrinter
import inql.Config
import inql.InQL
import inql.Logger
import inql.bruteforcer.Bruteforcer.Companion.NAME_REGEX
import inql.bruteforcer.Bruteforcer.RootOperationType
import inql.bruteforcer.Bruteforcer.RootTypeNames
import inql.exceptions.EmptyOrIncorrectWordlistException
import inql.graphql.GQLSchema
import inql.graphql.GraphQLSchemaToSDL
import inql.utils.ResourceFileReader
import java.io.File
import java.util.regex.Pattern
import java.util.*

class Bruteforcer2(private val inql: InQL) {
    private val WRONG_FIELD_EXAMPLE = "IAmWrongField"
    private val MAIN_REGEX = "[_0-9A-Za-z\\.\\[\\]!]+"
    private val REQUIRED_BUT_NOT_PROVIDED = "required(, but it was not provided| but not provided)?\\."

    private val FIELD_REGEXES = mapOf(
        "SKIP" to listOf(
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] must not have a selection since type ['\"]$MAIN_REGEX['\"] has no subfields\\."),
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] argument ['\"]$MAIN_REGEX['\"] of type ['\"]$MAIN_REGEX['\"] is $REQUIRED_BUT_NOT_PROVIDED"),
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"]$MAIN_REGEX['\"]\\."),
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"]($MAIN_REGEX)['\"]\\. Did you mean to use an inline fragment on ['\"]$MAIN_REGEX['\"]\\?"),
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"]($MAIN_REGEX)['\"]\\. Did you mean to use an inline fragment on ['\"]$MAIN_REGEX['\"] or ['\"]$MAIN_REGEX['\"]\\?"),
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"]($MAIN_REGEX)['\"]\\. Did you mean to use an inline fragment on (['\"]$MAIN_REGEX['\"], )+(or ['\"](?<last>$MAIN_REGEX)['\"])?\\?")
        ),
        "VALID_FIELD" to listOf(
            Pattern.compile("Field ['\"](?<field>$MAIN_REGEX)['\"] of type ['\"](?<typeref>$MAIN_REGEX)['\"] must have a selection of subfields\\. Did you mean ['\"]$MAIN_REGEX( \\{ \\.\\.\\. \\})?['\"]\\?"),
            Pattern.compile("Field ['\"](?<field>$MAIN_REGEX)['\"] of type ['\"](?<typeref>$MAIN_REGEX)['\"] must have a sub selection\\.")
        ),
        "SINGLE_SUGGESTION" to listOf(
            Pattern.compile("Cannot query field ['\"]($MAIN_REGEX)['\"] on type ['\"]$MAIN_REGEX['\"]\\. Did you mean ['\"](?<field>$MAIN_REGEX)['\"]\\?")
        ),
        "DOUBLE_SUGGESTION" to listOf(
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"]$MAIN_REGEX['\"]\\. Did you mean ['\"](?<one>$MAIN_REGEX)['\"] or ['\"](?<two>$MAIN_REGEX)['\"]\\?")
        ),
        "MULTI_SUGGESTION" to listOf(
            Pattern.compile("Cannot query field ['\"]($MAIN_REGEX)['\"] on type ['\"]$MAIN_REGEX['\"]\\. Did you mean (?<multi>(['\"]$MAIN_REGEX['\"], )+)(or ['\"](?<last>$MAIN_REGEX)['\"])?\\?")
        )
    )

    private val ARG_REGEXES = mapOf(
        "SKIP" to listOf(
            Pattern.compile("Unknown argument ['\"]$MAIN_REGEX['\"] on field ['\"]$MAIN_REGEX['\"]\\."),
            Pattern.compile("Unknown argument ['\"]$MAIN_REGEX['\"] on field ['\"]$MAIN_REGEX['\"] of type ['\"]$MAIN_REGEX['\"]\\."),
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] of type ['\"]$MAIN_REGEX['\"] must have a selection of subfields\\. Did you mean ['\"]$MAIN_REGEX( \\{ \\.\\.\\. \\})?['\"]\\?"),
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] argument ['\"]$MAIN_REGEX['\"] of type ['\"]$MAIN_REGEX['\"] is $REQUIRED_BUT_NOT_PROVIDED")
        ),
        "SINGLE_SUGGESTION" to listOf(
            Pattern.compile("Unknown argument ['\"]$MAIN_REGEX['\"] on field ['\"]$MAIN_REGEX['\"] of type ['\"]$MAIN_REGEX['\"]\\. Did you mean ['\"](?<arg>$MAIN_REGEX)['\"]\\?"),
            Pattern.compile("Unknown argument ['\"]$MAIN_REGEX['\"] on field ['\"]$MAIN_REGEX['\"]\\. Did you mean ['\"](?<arg>$MAIN_REGEX)['\"]\\?")
        ),
        "DOUBLE_SUGGESTION" to listOf(
            Pattern.compile("Unknown argument ['\"]$MAIN_REGEX['\"] on field ['\"]$MAIN_REGEX['\"]( of type ['\"]$MAIN_REGEX['\"])?\\. Did you mean ['\"](?<first>$MAIN_REGEX)['\"] or ['\"](?<second>$MAIN_REGEX)['\"]\\?")
        ),
        "MULTI_SUGGESTION" to listOf(
            Pattern.compile("Unknown argument ['\"]$MAIN_REGEX['\"] on field ['\"]$MAIN_REGEX['\"]\\. Did you mean (?<multi>(['\"]$MAIN_REGEX['\"], )+)(or ['\"](?<last>$MAIN_REGEX)['\"])?\\?")
        )
    )

    private val TYPEREF_REGEXES = mapOf(
        "FIELD" to listOf(
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] of type ['\"](?<typeref>$MAIN_REGEX)['\"] must have a selection of subfields\\. Did you mean ['\"]$MAIN_REGEX( \\{ \\.\\.\\. \\})?['\"]\\?"),
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] must not have a selection since type ['\"](?<typeref>$MAIN_REGEX)['\"] has no subfields\\."),
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"](?<typeref>$MAIN_REGEX)['\"]\\."),
            Pattern.compile("Cannot query field ['\"]$MAIN_REGEX['\"] on type ['\"](?<typeref>$MAIN_REGEX)['\"]\\. Did you mean [^\\?]+\\?"),
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] of type ['\"](?<typeref>$MAIN_REGEX)['\"] must not have a sub selection\\."),
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] of type ['\"](?<typeref>$MAIN_REGEX)['\"] must have a sub selection\\.")
        ),
        "ARG" to listOf(
            Pattern.compile("Field ['\"]$MAIN_REGEX['\"] argument ['\"]$MAIN_REGEX['\"] of type ['\"](?<typeref>$MAIN_REGEX)['\"] is $REQUIRED_BUT_NOT_PROVIDED"),
            Pattern.compile("Expected type (?<typeref>$MAIN_REGEX), found .+\\.")
        )
    )

    private val WRONG_TYPENAME = listOf(
        Pattern.compile("Cannot query field ['\"]$WRONG_FIELD_EXAMPLE['\"] on type ['\"](?<typename>$MAIN_REGEX)['\"]\\."),
        Pattern.compile("Field ['\"]$MAIN_REGEX['\"] must not have a selection since type ['\"](?<typename>$MAIN_REGEX)['\"] has no subfields\\."),
        Pattern.compile("Field ['\"]$MAIN_REGEX['\"] of type ['\"](?<typename>$MAIN_REGEX)['\"] must not have a sub selection\\.")
    )

    private val GENERAL_SKIP = listOf(
        Pattern.compile("String cannot represent a non string value: .+"),
        Pattern.compile("Float cannot represent a non numeric value: .+"),
        Pattern.compile("ID cannot represent a non-string and non-integer value: .+"),
        Pattern.compile("Enum ['\"]$MAIN_REGEX['\"] cannot represent non-enum value: .+"),
        Pattern.compile("Int cannot represent non-integer value: .+"),
        Pattern.compile("Not authorized")
    )

    private var BUCKET_SIZE = 64
    private var url: String = ""
    private var request: HttpRequest? = null
    private var bucketSize: Int = 64
    private var wordlist: List<String> = emptyList()

    fun startFromRequest(req: HttpRequest): String {
        url = req.url()
        request = req
        BUCKET_SIZE = Config.getInstance().getInt("bruteforcer.bucket_size") ?: 64

        var wordlistFile = Config.getInstance()
            .getString("bruteforcer.custom_wordlist")
            ?.takeIf { it.isNotEmpty() }
            ?: "wordlist.txt"

        loadWordlist(wordlistFile)

        return run()
    }

    private fun loadWordlist(wordlistFile: String) {
        val fileContent = when {
            wordlistFile == "wordlist.txt" -> ResourceFileReader.readFile(wordlistFile)
            else -> File(wordlistFile).takeIf { it.exists() }?.readText()
        } ?: throw EmptyOrIncorrectWordlistException("Wordlist file not found: $wordlistFile")

        if (fileContent.isEmpty()) {
            throw EmptyOrIncorrectWordlistException("Wordlist is empty")
        }

        wordlist = fileContent.lineSequence()
            .filter { it.isNotBlank() }
            .filter { word -> NAME_REGEX.matches(word) }
            .toList()

        if (wordlist.isEmpty()) {
            throw EmptyOrIncorrectWordlistException("All words in the wordlist are invalid")
        }
    }

    fun run(): String {
        val validatedWordlist = wordlist


        var currentSchema: GraphQLSchema? = null
        var ignored = GraphQLPrimitive.values().map { it.name }.toMutableSet()
        var currentDocument = "query { FUZZ }"
        var iterations = 1
        var lastSDL = ""

        while (true) {
            iterations++

            lastSDL = clairvoyance(
                validatedWordlist,
                currentDocument,
                request!!,
                currentSchema
            )

            currentSchema = parseSchema(lastSDL)
            val nextType = getNextTypeToExplore(currentSchema, ignored)

            if (nextType == null) {
                break
            }

            ignored.add(nextType)
            currentDocument = buildQueryDocument(currentSchema, nextType)
        }

        return lastSDL
    }

    private fun parseSchema(sdl: String): GraphQLSchema {
        val typeRegistry = SchemaParser().parse(sdl)
        return SchemaGenerator().makeExecutableSchema(typeRegistry, RuntimeWiring.newRuntimeWiring().build())
    }

    enum class GraphQLPrimitive {
        String, Int, Float, Boolean, ID
    }

    private fun findPathToType(schema: GraphQLSchema, startType: String, targetType: String): List<String> {
        val visited = mutableSetOf<String>()
        val queue: Queue<Pair<String, List<String>>> = LinkedList()
        queue.add(startType to emptyList())

        while (queue.isNotEmpty()) {
            val (currentType, path) = queue.poll()
            if (currentType in visited) continue
            visited.add(currentType)

            val typeDef = schema.getType(currentType) as? GraphQLObjectType ?: continue

            for (field in typeDef.fieldDefinitions) {
                val fieldType = getBaseTypeName(field.type)
                val newPath = path + field.name

                if (fieldType == targetType) {
                    return newPath
                }

                if (fieldType !in visited) {
                    queue.add(fieldType to newPath)
                }
            }
        }
        return emptyList()
    }

    private fun buildQueryDocument(schema: GraphQLSchema, targetType: String): String {
        val queryType = schema.queryType.name
        val path = findPathToType(schema, queryType, targetType)
        return if (path.isNotEmpty()) {
            "query { ${buildNestedFields(path)} }"
        } else {
            "query { FUZZ }"
        }
    }

    private fun buildNestedFields(path: List<String>): String {
        return path.foldRight("FUZZ") { field, inner -> "$field { $inner }" }
    }

    private fun getNextTypeToExplore(schema: GraphQLSchema, ignored: Set<String>): String? {
        return schema.typeMap.values
            .filter { it.name !in ignored }
            .filterIsInstance<GraphQLObjectType>()
            .firstOrNull { type ->
                type.fieldDefinitions.isEmpty() || type.fieldDefinitions.all { field ->
                    val typeName = getBaseTypeName(field.type)
                    typeName in ignored
                }
            }?.name
    }

    private fun getBaseTypeName(type: GraphQLType): String {
        return when (val unwrapped = unwrapType(type)) {
            is GraphQLObjectType -> unwrapped.name
            is GraphQLInterfaceType -> unwrapped.name
            is GraphQLUnionType -> unwrapped.name
            is GraphQLEnumType -> unwrapped.name
            is GraphQLScalarType -> unwrapped.name
            else -> ""
        }
    }

    fun clairvoyance(
        wordlist: List<String>,
        inputDocument: String,
        request: HttpRequest,
        inputSchema: GraphQLSchema? = null
    ): String {
        var schema = inputSchema
        if (schema == null) {
            var rootTypenames = fetchRootTypeNames()
            schema = buildSchemaFromRootNames(rootTypenames)
        }
        val typename = probeTypename(inputDocument, request)
        val validFields = probeValidFields(wordlist, inputDocument, request)

        val fields = mutableListOf<GraphQLFieldDefinition>()
        val additionalTypes = mutableSetOf<GraphQLType>()

        for (fieldName in validFields) {
            val (field, args) = exploreField(fieldName, inputDocument, wordlist, typename, request)
            fields.add(field)
            additionalTypes.addAll(args.map { it.type })
        }

        val queryType = GraphQLObjectType.newObject()
            .name(typename)
            .fields(fields)
            .build()

        return SchemaPrinter().print(
            GraphQLSchema.newSchema(schema)
                .query(queryType)
                .additionalTypes(additionalTypes)
                .build()
        )
    }

    private fun buildSchemaFromRootNames(rootNames: RootTypeNames): GraphQLSchema {
        val types = listOfNotNull(
            rootNames.queryType,
            rootNames.mutationType,
            rootNames.subscriptionType
        ).associateWith { typeName ->
            GraphQLObjectType.newObject().name(typeName).field {
                @Suppress("DEPRECATION")
                it.name("ping").type(Scalars.GraphQLString).dataFetcher { "pong" }
            }.build()
        }

        val schemaBuilder = GraphQLSchema.newSchema()

        rootNames.queryType?.let { typeName ->
            schemaBuilder.query(types[typeName]
                ?: throw IllegalArgumentException("Query type '$typeName' not found in types map.")
            )
        }

        rootNames.mutationType?.let { typeName ->
            schemaBuilder.mutation(types[typeName]
                ?: throw IllegalArgumentException("Mutation type '$typeName' not found in types map.")
            )
        }

        rootNames.subscriptionType?.let { typeName ->
            schemaBuilder.subscription(types[typeName]
                ?: throw IllegalArgumentException("Subscription type '$typeName' not found in types map.")
            )
        }

        return schemaBuilder.build()
    }

    private fun probeValidFields(
        wordlist: List<String>,
        inputDocument: String,
        request: HttpRequest
    ): Set<String> {
        val validFields = mutableSetOf<String>()
        var i = 0
        while (i < wordlist.size) {
            val bucket = wordlist.subList(i, minOf(i + BUCKET_SIZE, wordlist.size))
            validFields.addAll(probeValidFieldsBucket(bucket, inputDocument, request))
            i += BUCKET_SIZE
        }
        return validFields
    }

    private fun probeValidFieldsBucket(
        bucket: List<String>,
        inputDocument: String,
        request: HttpRequest
    ): Set<String> {
        val document = inputDocument.replace("FUZZ", bucket.joinToString(" "))
        val response = Utils.sendGraphQLRequest(document, request)
        val errors = when (val e = response["errors"]) {
            is List<*> -> e.filterIsInstance<Map<String, Any>>()
            else -> emptyList()
        }
        if (errors.isEmpty()) return bucket.toSet()

        val validFields = bucket.toMutableSet()
        for (error in errors) {
            val errorMessage = error["message"] as? String ?: continue
            if (isSkippableError(errorMessage)) continue
            extractValidFields(errorMessage, validFields)
        }
        return validFields
    }

    private fun isSkippableError(errorMessage: String): Boolean {
        return (FIELD_REGEXES["SKIP"]?.any { it.matcher(errorMessage).matches() } == true ||
                GENERAL_SKIP.any { it.matcher(errorMessage).matches() })
    }

    private fun extractValidFields(errorMessage: String, validFields: MutableSet<String>) {
        for (regex in FIELD_REGEXES["VALID_FIELD"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                validFields.add(matcher.group("field"))
                return
            }
        }

        for (regex in FIELD_REGEXES["SINGLE_SUGGESTION"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                validFields.add(matcher.group("field"))
                return
            }
        }

        for (regex in FIELD_REGEXES["DOUBLE_SUGGESTION"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                validFields.add(matcher.group("one"))
                validFields.add(matcher.group("two"))
                return
            }
        }

        for (regex in FIELD_REGEXES["MULTI_SUGGESTION"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                matcher.group("multi")?.split(", ")?.forEach {
                    validFields.add(it.trim('\'', '"'))
                }
                matcher.group("last")?.let { validFields.add(it) }
                return
            }
        }
    }

    private fun probeTypename(inputDocument: String, request: HttpRequest): String {
        val document = inputDocument.replace("FUZZ", WRONG_FIELD_EXAMPLE)
        val response = Utils.sendGraphQLRequest(document, request)
        val errors = when (val e = response["errors"]) {
            is List<*> -> e.filterIsInstance<Map<String, Any>>()
            else -> emptyList()
        }

        for (error in errors) {
            val errorMessage = error["message"] as? String ?: continue
            for (regex in WRONG_TYPENAME) {
                val matcher = regex.matcher(errorMessage)
                if (matcher.matches()) {
                    return matcher.group("typename")?.replace("[\\[\\]!]".toRegex(), "") ?: "Query"
                }
            }
        }
        return "Query"
    }

//    private fun fetchRootTypenames(request: HttpRequest): GraphQLSchema {
//        val documents = mapOf(
//            "queryType" to "query { __typename }",
//            "mutationType" to "mutation { __typename }",
//            "subscriptionType" to "subscription { __typename }"
//        )
//
//        val typenames = mutableMapOf<String, String?>()
//        for ((name, document) in documents) {
//            val response = Utils.sendGraphQLRequest(document, request)
//            val data = response["data"] as? Map<*, *>
//            typenames[name] = data?.get("__typename") as? String
//        }
//
//        return GraphQLSchema.newSchema().build()
//    }

    private fun fetchRootTypeNames(): RootTypeNames {
        val result = mutableMapOf<RootOperationType, String?>()

        for (opType in RootOperationType.values()) {
            val document = "${opType.keyword} { __typename }"
            try {
                val json = Utils.sendGraphQLRequest(document, request!!)
                val typename = json.optJSONObject("data")?.optString("__typename")
                if (typename != null) {
                    result[opType] = typename
                }
            } catch (e: Exception) {
                println("Error fetching ${opType.name.lowercase()}: ${e.message}")
                result[opType] = null
            }
        }

        val rootNames = RootTypeNames(
            queryType = result[RootOperationType.QUERY],
            mutationType = result[RootOperationType.MUTATION],
            subscriptionType = result[RootOperationType.SUBSCRIPTION]
        )

        return rootNames
    }

    private fun exploreField(
        fieldName: String,
        inputDocument: String,
        wordlist: List<String>,
        typename: String,
        request: HttpRequest
    ): Pair<GraphQLFieldDefinition, List<GraphQLArgument>> {
        val fieldType = probeFieldType(fieldName, inputDocument, request)
        val args = mutableListOf<GraphQLArgument>()

        if (fieldType !is GraphQLScalarType) {
            val argNames = probeArgs(fieldName, wordlist, inputDocument, request)
            for (argName in argNames) {
                val argType = probeArgTyperef(fieldName, argName, inputDocument, request)
                if (argType != null) {
                    args.add(GraphQLArgument.newArgument().name(argName).type(argType).build())
                }
            }
        }

        val field = GraphQLFieldDefinition.newFieldDefinition()
            .name(fieldName)
            .type(fieldType ?: GraphQLString)
            .arguments(args)
            .build()

        return Pair(field, args)
    }

    private fun probeFieldType(
        field: String,
        inputDocument: String,
        request: HttpRequest
    ): GraphQLOutputType? {
        val documents = listOf(
            inputDocument.replace("FUZZ", field),
            inputDocument.replace("FUZZ", "$field { lol }")
        )
        return probeTyperef(documents, FuzzingContext.FIELD, request) as? GraphQLOutputType
    }

    private fun probeArgs(
        field: String,
        wordlist: List<String>,
        inputDocument: String,
        request: HttpRequest
    ): Set<String> {
        val validArgs = mutableSetOf<String>()
        var i = 0
        while (i < wordlist.size) {
            val bucket = wordlist.subList(i, minOf(i + BUCKET_SIZE, wordlist.size))
            validArgs.addAll(probeValidArgs(field, bucket, inputDocument, request))
            i += BUCKET_SIZE
        }
        return validArgs
    }

    private fun probeValidArgs(
        field: String,
        wordlist: List<String>,
        inputDocument: String,
        request: HttpRequest
    ): Set<String> {
        val argsString = wordlist.joinToString(", ") { "$it: 7" }
        val document = inputDocument.replace("FUZZ", "$field($argsString)")
        val response = Utils.sendGraphQLRequest(document, request)
        val errors = when (val e = response["errors"]) {
            is List<*> -> e.filterIsInstance<Map<String, Any>>()
            else -> emptyList()
        }
        if (errors.isEmpty()) return wordlist.toSet()

        val validArgs = wordlist.toMutableSet()
        for (error in errors) {
            val errorMessage = error["message"] as? String ?: continue
            if (isSkippableArgError(errorMessage)) continue
            extractValidArgs(errorMessage, validArgs)
        }
        return validArgs
    }

    private fun isSkippableArgError(errorMessage: String): Boolean {
        return (ARG_REGEXES["SKIP"]?.any { it.matcher(errorMessage).matches() } == true ||
                GENERAL_SKIP.any { it.matcher(errorMessage).matches() })
    }

    private fun extractValidArgs(errorMessage: String, validArgs: MutableSet<String>) {
        for (regex in ARG_REGEXES["SINGLE_SUGGESTION"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                validArgs.add(matcher.group("arg"))
                return
            }
        }

        for (regex in ARG_REGEXES["DOUBLE_SUGGESTION"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                validArgs.add(matcher.group("first"))
                validArgs.add(matcher.group("second"))
                return
            }
        }

        for (regex in ARG_REGEXES["MULTI_SUGGESTION"] ?: emptyList()) {
            val matcher = regex.matcher(errorMessage)
            if (matcher.matches()) {
                matcher.group("multi")?.split(", ")?.forEach {
                    validArgs.add(it.trim('\'', '"'))
                }
                matcher.group("last")?.let { validArgs.add(it) }
                return
            }
        }
    }

    private fun probeArgTyperef(
        field: String,
        arg: String,
        inputDocument: String,
        request: HttpRequest
    ): GraphQLInputType? {
        val documents = listOf(
            inputDocument.replace("FUZZ", "$field($arg: 42)"),
            inputDocument.replace("FUZZ", "$field($arg: {})"),
            inputDocument.replace("FUZZ", "$field(${arg.dropLast(1)}: 42)"),
            inputDocument.replace("FUZZ", "$field($arg: \"42\")"),
            inputDocument.replace("FUZZ", "$field($arg: false)")
        )
        return probeTyperef(documents, FuzzingContext.ARGUMENT, request) as? GraphQLInputType
    }

    private fun probeTyperef(
        documents: List<String>,
        context: FuzzingContext,
        request: HttpRequest
    ): GraphQLType? {
        for (document in documents) {
            val response = Utils.sendGraphQLRequest(document, request)
            val errors = when (val e = response["errors"]) {
                is List<*> -> e.filterIsInstance<Map<String, Any>>()
                else -> emptyList()
            }
            for (error in errors) {
                val errorMessage = error["message"] as? String ?: continue
                val typeref = getTyperef(errorMessage, context)
                if (typeref != null) return typeref
            }
        }
        return null
    }

    private fun getTyperef(
        errorMessage: String,
        context: FuzzingContext
    ): GraphQLType? {
        val match = extractMatchingFields(errorMessage, context)
        val tk = match?.group(1) ?: return null

        val name = tk.replace("[\\[\\]!]".toRegex(), "")
        val kind = when {
            name in setOf("String", "Int", "Float", "Boolean", "ID") -> "SCALAR"
            context == FuzzingContext.FIELD -> "OBJECT"
            context == FuzzingContext.ARGUMENT -> "INPUT_OBJECT"
            else -> return null
        }

        val isList = tk.contains('[') && tk.contains(']')
        val nonNullItem = isList && tk.contains("!]")
        val nonNull = tk.endsWith('!')

        var graphQLType: GraphQLType = when (kind) {
            "SCALAR" -> when (name) {
                "String" -> GraphQLString
                "Int" -> GraphQLInt
                "Float" -> GraphQLFloat
                "Boolean" -> GraphQLBoolean
                "ID" -> GraphQLID
                else -> GraphQLString
            }
            "OBJECT" -> GraphQLObjectType.newObject().name(name).build()
            "INPUT_OBJECT" -> GraphQLInputObjectType.newInputObject().name(name).build()
            else -> return null
        }

        if (isList) {
            var itemType = graphQLType
            if (nonNullItem) itemType = GraphQLNonNull.nonNull(itemType)
            graphQLType = GraphQLList.list(itemType)
        }
        if (nonNull) graphQLType = GraphQLNonNull.nonNull(graphQLType)

        return graphQLType
    }

    private fun extractMatchingFields(
        errorMessage: String,
        context: FuzzingContext
    ): java.util.regex.MatchResult? {
        return when (context) {
            FuzzingContext.FIELD -> {
                if (TYPEREF_REGEXES["ARG"]?.any { it.matcher(errorMessage).matches() } == true) return null
                TYPEREF_REGEXES["FIELD"]?.firstNotNullOfOrNull { it.matcher(errorMessage).takeIf { it.matches() } }
            }
            FuzzingContext.ARGUMENT -> {
                if (TYPEREF_REGEXES["FIELD"]?.any { it.matcher(errorMessage).matches() } == true) return null
                TYPEREF_REGEXES["ARG"]?.firstNotNullOfOrNull { it.matcher(errorMessage).takeIf { it.matches() } }
            }
        }
    }

    enum class FuzzingContext {
        FIELD, ARGUMENT
    }
}