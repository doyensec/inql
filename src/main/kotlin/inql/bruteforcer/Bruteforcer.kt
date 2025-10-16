package inql.bruteforcer

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.Scalars.*
import graphql.language.*
import graphql.schema.*
import inql.Config
import inql.InQL
import inql.Logger
import inql.exceptions.EmptyOrIncorrectWordlistException
import inql.graphql.GraphQLSchemaToSDL
import inql.utils.ResourceFileReader
import kotlinx.coroutines.yield
import java.io.File
import java.util.*
import kotlin.math.min

/**
 * A utility object to store regular expressions used for parsing GraphQL error messages.
 * This is central to Clairvoyance's technique of schema reconstruction.
 */
object RegexStore {
    // --- Constants ---

    // A regex part for matching a standard GraphQL name.
    private const val GQL_NAME_PART = "[_A-Za-z][_0-9A-Za-z]*"
    // A more permissive regex part for matching type references, which can include '[]' and '!'.
    private const val GQL_TYPE_REF_PART = "[_0-9A-Za-z\\.\\[\\]!]+"

    // Fake field/arg names used to trigger specific error messages.
    const val WRONG_FIELD_EXAMPLE = "____i_n_q_l____"
    const val WRONG_ARG_EXAMPLE = "____i_n_q_l____"

    // --- Regex Definitions ---

    // For extracting the current type name from an error message.
    val EXTRACT_TYPE_NAME = listOf(
        Regex("""Cannot query field ['"]$WRONG_FIELD_EXAMPLE['"] on type ['"](?<typename>$GQL_TYPE_REF_PART)['"]\."""),
        Regex("""Cannot query field ['"]$GQL_NAME_PART['"] on type ['"](?<typename>$GQL_TYPE_REF_PART)['"]\."""),
        Regex("""Field ['"]$GQL_NAME_PART['"] is not defined by type ['"](?<typename>$GQL_TYPE_REF_PART)['"]\."""),
        Regex("""Field '(?<field>$GQL_NAME_PART)' is not defined on type '(?<typename>$GQL_NAME_PART)'.(.*)"""),
    )

    // For extracting field suggestions. Covers single, double, and multiple suggestions.
    val FIELD_SUGGESTIONS = listOf(
        // Single suggestions (covers both 'Did you mean "suggestion"?' and 'Did you mean `suggestion`?')
        Regex("""Did you mean ['"](?<suggestion>$GQL_NAME_PART)['"]\?"""),
        Regex("""Cannot query field ['"]$GQL_NAME_PART['"] on type ['"]$GQL_TYPE_REF_PART['"]\. Did you mean ['"](?<suggestion>$GQL_NAME_PART)['"]\?"""),
        // Double suggestions
        Regex("""Cannot query field ['"]$GQL_NAME_PART['"] on type ['"]$GQL_TYPE_REF_PART['"]\. Did you mean ['"](?<one>$GQL_NAME_PART)['"] or ['"](?<two>$GQL_NAME_PART)['"]\?"""),
        // Multiple suggestions
        Regex("""Cannot query field ['"]$GQL_NAME_PART['"] on type ['"]$GQL_TYPE_REF_PART['"]\. Did you mean (?<multi>(?:['"]$GQL_NAME_PART['"],? )+)(?:or ['"](?<last>$GQL_NAME_PART)['"])?\?""")
    )

    // For extracting argument suggestions.
    val ARGUMENT_SUGGESTIONS = listOf(
        // Single suggestions
        Regex("""Unknown argument ['"]$GQL_NAME_PART['"] on field ['"]$GQL_NAME_PART['"](?: of type ['"]$GQL_TYPE_REF_PART['"])?\. Did you mean ['"](?<suggestion>$GQL_NAME_PART)['"]\?"""),
        // Double suggestions
        Regex("""Unknown argument ['"]$GQL_NAME_PART['"] on field ['"]$GQL_NAME_PART['"](?: of type ['"]$GQL_TYPE_REF_PART['"])?\. Did you mean ['"](?<one>$GQL_NAME_PART)['"] or ['"](?<two>$GQL_NAME_PART)['"]\?"""),
        // Multiple suggestions
        Regex("""Unknown argument ['"]$GQL_NAME_PART['"] on field ['"]$GQL_NAME_PART['"](?: of type ['"]$GQL_TYPE_REF_PART['"])?\. Did you mean (?<multi>(?:['"]$GQL_NAME_PART['"],? )+)(?:or ['"](?<last>$GQL_NAME_PART)['"])?\?""")
    )

    // For identifying when a sub-selection is attempted on a scalar type.
    val NO_SUBFIELDS =
        Regex("""Field ['"](?<field>$GQL_NAME_PART)['"] must not have a selection since type ['"]?(?<type>$GQL_TYPE_REF_PART)['"]? has no subfields\.*""")

    // For finding missing required arguments and their types.
    val MISSING_ARGUMENT =
        Regex("""Field ['"](?<field>$GQL_NAME_PART)['"] argument ['"](?<argument>$GQL_NAME_PART)['"] of type ['"](?<type>$GQL_TYPE_REF_PART)['"] is required but not provided.""")

    // For finding an argument's type when the wrong type is provided.
    val WRONG_ARGUMENT_TYPE = Regex(
        """Argument ['"](?<argument>$GQL_NAME_PART)['"] has invalid value .*\. Expected type ['"]?(?<type>$GQL_TYPE_REF_PART)['"]?,"""
    )

    // For identifying fields that are explicitly invalid, to aid in process-of-elimination.
    val INVALID_FIELD = listOf(
        Regex("""Cannot query field ['"](?<field>$GQL_NAME_PART)['"] on type ['"]$GQL_TYPE_REF_PART['"]\."""),
        Regex("""Field ['"](?<field>$GQL_NAME_PART)['"] is not defined by type ['"]$GQL_TYPE_REF_PART['"]\."""),
        Regex("""Field '(?<field>$GQL_NAME_PART)' is not defined on type '(?<typename>$GQL_NAME_PART)'.(.*)""")
    )

    val VALIDATION_ERROR_LIMIT = Regex("""Too many validation errors, error limit reached""")

    /**
     * A comprehensive suggestion extractor that handles single, double, and multi-suggestion error messages.
     * It checks for named groups: 'suggestion', 'one', 'two', 'multi', and 'last'.
     */
    fun getSuggestions(errorMessage: String, regexList: List<Regex>): List<String> {
        val suggestions = mutableListOf<String>()
        for (regex in regexList) {
            regex.findAll(errorMessage).forEach { matchResult ->
                matchResult.groups["suggestion"]?.value?.let { suggestions.add(it) }
                matchResult.groups["one"]?.value?.let { suggestions.add(it) }
                matchResult.groups["two"]?.value?.let { suggestions.add(it) }
                matchResult.groups["last"]?.value?.let { suggestions.add(it) }
                matchResult.groups["multi"]?.value?.let { multi ->
                    // The 'multi' group captures a list like "'arg1', 'arg2', ". We need to extract them.
                    val multiRegex = Regex("['\"]($GQL_NAME_PART)['\"]")
                    multiRegex.findAll(multi).mapTo(suggestions) { it.groupValues[1] }
                }
            }
        }
        return suggestions.distinct()
    }
}

/**
 * Main class for bruteforcing the GraphQL schema.
 * This class orchestrates the entire process of schema discovery, from finding root types
 * to recursively scanning each object type for its fields and arguments.
 */
class Bruteforcer(private val inql: InQL) {
    private var request: HttpRequest? = null
    private var bucketSize: Int = 64
    private var wordlist: List<String> = emptyList()

    companion object {
        val NAME_REGEX = Regex("^[_A-Za-z][_0-9A-Za-z]*$")
        val BUILT_IN_SCALARS = setOf(
            GraphQLString.name,
            GraphQLInt.name,
            GraphQLFloat.name,
            GraphQLBoolean.name,
            GraphQLID.name
        )
    }

    // Data classes to hold schema information
    data class RootTypeNames(
        val queryType: String? = "Query",
        val mutationType: String? = null,
        val subscriptionType: String? = null
    )

    /**
     * Entry point to start the schema bruteforcing process from an HTTP request.
     */
    suspend fun startFromRequest(req: HttpRequest): String {
        request = req
        bucketSize = Config.getInstance().getInt("bruteforcer.bucket_size") ?: 64

        val wordlistFile = Config.getInstance()
            .getString("bruteforcer.custom_wordlist")
            ?.takeIf { it.isNotEmpty() }
            ?: "wordlist.txt"

        loadWordlist(wordlistFile)

        val schema = run()
        return GraphQLSchemaToSDL.schemaToSDL(schema)
    }

    /**
     * Loads and filters the wordlist from a file.
     */
    private fun loadWordlist(wordlistFile: String) {
        val fileContent = when {
            wordlistFile == "wordlist.txt" -> ResourceFileReader.readFile(wordlistFile)
            else -> File(wordlistFile).takeIf { it.exists() }?.readText()
        } ?: throw EmptyOrIncorrectWordlistException("Wordlist file not found: $wordlistFile")

        if (fileContent.isEmpty()) {
            throw EmptyOrIncorrectWordlistException("Wordlist is empty")
        }

        wordlist = fileContent.lineSequence()
            .filter { it.isNotBlank() && NAME_REGEX.matches(it) }
            .distinct()
            .toList()

        if (wordlist.isEmpty()) {
            throw EmptyOrIncorrectWordlistException("No valid words in the wordlist")
        }
    }

    /**
     * The main execution loop for schema discovery.
     */
    private suspend fun run(): GraphQLSchema {
        val rootTypeNames = fetchRootTypeNames()
        var schema = buildInitialSchema(rootTypeNames)

        val typesToScan = LinkedList<String>()
        rootTypeNames.queryType?.let { typesToScan.add(it) }
        rootTypeNames.mutationType?.let { typesToScan.add(it) }
        rootTypeNames.subscriptionType?.let { typesToScan.add(it) }

        val scannedTypes = mutableSetOf<String>()

        while (typesToScan.isNotEmpty()) {
            yield()

            val currentTypeName = typesToScan.poll()
            if (currentTypeName in scannedTypes || currentTypeName in BUILT_IN_SCALARS) {
                continue
            }

            Logger.debug("Scanning type: $currentTypeName")
            val pathToType = findPathToType(schema, currentTypeName)
            // FIXED: Added the missing 'schema' argument to the call below
            val scanQuery = convertPathToQuery(pathToType, schema)

            val result = scanType(scanQuery, currentTypeName, schema)
            schema = result.first
            scannedTypes.add(currentTypeName)

            result.second.forEach { newType ->
                if (newType !in scannedTypes && newType !in typesToScan) {
                    typesToScan.add(newType)
                }
            }
        }
        return schema
    }


    /**
     * Probes the endpoint to find the names of the root operation types.
     */
    private fun fetchRootTypeNames(): RootTypeNames {
        // A schema must have a query type. Default to "Query" if detection fails.
        val queryType = probeTypename("query { ${RegexStore.WRONG_FIELD_EXAMPLE} }") ?: "Query"

        // For mutation and subscription, if probing returns null, it means the operation
        // is not supported, so we keep them as null.
        val mutationType = probeTypename("mutation { ${RegexStore.WRONG_FIELD_EXAMPLE} }")
        val subscriptionType = probeTypename("subscription { ${RegexStore.WRONG_FIELD_EXAMPLE} }")

        Logger.debug("Discovered root types -> Query: $queryType, Mutation: $mutationType, Subscription: $subscriptionType")

        return RootTypeNames(queryType, mutationType, subscriptionType)
    }

    /**
     * Builds the initial GraphQLSchema object with root types defined.
     */
    private fun buildInitialSchema(rootNames: RootTypeNames): GraphQLSchema {
        val schemaBuilder = GraphQLSchema.newSchema()

        // Define a temporary field to make the initial object types valid
        val placeholderField = GraphQLFieldDefinition.newFieldDefinition()
            .name("_inql_placeholder")
            .type(GraphQLString)
            .build()

        rootNames.queryType?.let {
            val type = GraphQLObjectType.newObject()
                .name(it)
                .field(placeholderField) // Add placeholder
                .build()
            schemaBuilder.query(type)
        }
        rootNames.mutationType?.let {
            val type = GraphQLObjectType.newObject()
                .name(it)
                .field(placeholderField) // Add placeholder
                .build()
            schemaBuilder.mutation(type)
        }
        rootNames.subscriptionType?.let {
            val type = GraphQLObjectType.newObject()
                .name(it)
                .field(placeholderField) // Add placeholder
                .build()
            schemaBuilder.subscription(type)
        }
        return schemaBuilder.build()
    }

    /**
     * Finds a path of fields from a root type to a target type.
     */
    private fun findPathToType(schema: GraphQLSchema, targetTypeName: String): List<String> {
        val roots = listOfNotNull(schema.queryType, schema.mutationType, schema.subscriptionType)
        if (targetTypeName in roots.map { it.name }) return listOf(targetTypeName)

        val visitedTypes = mutableSetOf<String>()
        val queue: Queue<List<String>> = LinkedList()

        roots.forEach { root ->
            queue.add(listOf(root.name))
            visitedTypes.add(root.name)
        }

        while (queue.isNotEmpty()) {
            val path = queue.poll()

            // Resolve the current type at the end of the path
            var currentType: GraphQLType = schema.getType(path.first()) as GraphQLType
            for (fieldName in path.drop(1)) {
                val container = GraphQLTypeUtil.unwrapAll(currentType) as? GraphQLFieldsContainer
                    ?: break // Stop if we hit a scalar
                val fieldDef = container.getFieldDefinition(fieldName) ?: break
                currentType = fieldDef.type
            }

            val currentObjectType = GraphQLTypeUtil.unwrapAll(currentType) as? GraphQLObjectType ?: continue

            for (field in currentObjectType.fieldDefinitions) {
                val fieldTypeName = GraphQLTypeUtil.unwrapAll(field.type).name
                if (fieldTypeName == targetTypeName) {
                    return path + field.name
                }

                if (fieldTypeName !in visitedTypes && schema.getType(fieldTypeName) is GraphQLObjectType) {
                    visitedTypes.add(fieldTypeName)
                    queue.add(path + field.name)
                }
            }
        }
        throw IllegalStateException("Could not find path to type $targetTypeName")
    }

    /**
     * Converts a path array into a GraphQL query string for scanning.
     */
    private fun convertPathToQuery(path: List<String>, schema: GraphQLSchema): String {
        val operationName = schema.queryType?.takeIf { it.name == path.first() }?.let { "query" }
            ?: schema.mutationType?.takeIf { it.name == path.first() }?.let { "mutation" }
            ?: "subscription"

        var queryBody = ""
        var currentPathType: GraphQLType = schema.getType(path.first()) as GraphQLType

        path.drop(1).forEach { fieldName ->
            val container = GraphQLTypeUtil.unwrapAll(currentPathType) as? GraphQLFieldsContainer
                ?: throw IllegalStateException("Type '${(currentPathType as? GraphQLNamedType)?.name}' is not a fields container.")

            val fieldDef = container.getFieldDefinition(fieldName)
                ?: throw IllegalStateException("Field '$fieldName' not found on type '${container.name}'")

            currentPathType = fieldDef.type

            val argsString = fieldDef.arguments
                .filter { GraphQLTypeUtil.isNonNull(it.type) }
                .joinToString(", ") {
                    val value = when (GraphQLTypeUtil.unwrapAll(it.type).name) {
                        "String" -> "\"\""
                        "ID" -> "\"1\""
                        "Int" -> "0"
                        "Float" -> "0.0"
                        "Boolean" -> "false"
                        else -> "{}" // For input objects
                    }
                    "${it.name}: $value"
                }

            queryBody += if (argsString.isNotEmpty()) "$fieldName($argsString) { " else "$fieldName { "
        }

        queryBody += "FUZZ" + " }".repeat(path.size - 1)

        return "$operationName { $queryBody }"
    }



    /**
     * Probes an endpoint with a placeholder query to get the name of the current type.
     */
    private fun probeTypename(inputDocument: String): String? {
        val document = inputDocument.replace("FUZZ", RegexStore.WRONG_FIELD_EXAMPLE)
        try {
            val response = Utils.sendGraphQLRequest(document, request!!)
            val errors = response.optJSONArray("errors") ?: return null

            val allErrorMessages = (0 until errors.length()).joinToString("\n") {
                errors.getJSONObject(it).optString("message", "")
            }

            if (allErrorMessages.contains("Schema is not configured for")) return null

            // Check for a scalar type response first, as it's the most specific.
            RegexStore.NO_SUBFIELDS.find(allErrorMessages)?.groups?.get("type")?.value?.let {
                return it.replace(Regex("[\\[\\]!]"), "")
            }

            // Then, check for standard "wrong field on type X" errors.
            for (regex in RegexStore.EXTRACT_TYPE_NAME) {
                regex.find(allErrorMessages)?.groups?.get("typename")?.value?.let {
                    return it.replace(Regex("[\\[\\]!]"), "")
                }
            }

            Logger.debug("Could not determine typename from error: $errors. Returning null.")
            return null
        } catch (e: Exception) {
            Logger.error("Exception during probeTypename for document '$document': ${e.message}")
            return null
        }
    }

    /**
     * Performs the core scan on a single type to find its fields, their types, and arguments.
     * This version intelligently reclassifies objects with no discovered fields as custom scalars.
     */
    private suspend fun scanType(scanQuery: String, typeName: String, schema: GraphQLSchema): Pair<GraphQLSchema, Set<String>> {
        // --- ADDED: Make the function cooperative for cancellation ---
        yield()

        val validFields = probeValidFields(scanQuery)
        val newTypesFound = mutableSetOf<String>()
        val currentSchema = schema
        val typeMap = currentSchema.typeMap.toMutableMap()

        // If we found no fields, we reclassify this type as a custom scalar.
        if (validFields.isEmpty()) {
            Logger.debug("No fields found for '$typeName'. Reclassifying as a custom scalar.")
            val newScalar = GraphQLScalarType.newScalar()
                .name(typeName)
                .coercing(object : Coercing<Any, Any> {
                    override fun serialize(dataFetcherResult: Any): Any = dataFetcherResult
                    override fun parseValue(input: Any): Any = input
                    override fun parseLiteral(input: Any): Any = input
                })
                .build()
            typeMap[typeName] = newScalar
        } else {
            // If we found fields, build the object type as normal.
            val typeBuilder = GraphQLObjectType.newObject(currentSchema.getObjectType(typeName))
                .clearFields()

            for (fieldName in validFields) {
                // --- ADDED: Make the inner loop cooperative for cancellation ---
                yield()
                Logger.debug("Found field: $fieldName on type $typeName")
                val fieldQuery = scanQuery.replace("FUZZ", "$fieldName { ${RegexStore.WRONG_FIELD_EXAMPLE} }")
                val fieldTypeName = probeTypename(fieldQuery) ?: "String"
                newTypesFound.add(fieldTypeName)
                val arguments = probeValidArguments(scanQuery.replace("FUZZ", fieldName))
                val fieldDefBuilder = GraphQLFieldDefinition.newFieldDefinition()
                    .name(fieldName)
                    .type(GraphQLTypeReference(fieldTypeName))
                for (argName in arguments) {
                    val argQuery = scanQuery.replace("FUZZ", "$fieldName($argName: ${RegexStore.WRONG_ARG_EXAMPLE})")
                    val argTypeName = probeArgumentType(argQuery, fieldName, argName)
                    newTypesFound.add(argTypeName)
                    fieldDefBuilder.argument(
                        GraphQLArgument.newArgument().name(argName).type(GraphQLTypeReference(argTypeName)).build()
                    )
                }
                typeBuilder.field(fieldDefBuilder.build())
            }
            typeMap[typeName] = typeBuilder.build()
        }

        // Add placeholders for any newly discovered types that have not been scanned yet.
        newTypesFound.forEach {
            if (it !in typeMap && it !in BUILT_IN_SCALARS) {
                val placeholderField = GraphQLFieldDefinition.newFieldDefinition()
                    .name("_inql_placeholder")
                    .type(GraphQLString)
                    .build()
                typeMap[it] = GraphQLObjectType.newObject().name(it).field(placeholderField).build()
            }
        }

        // Rebuild the schema with our updated typemap.
        val newSchema = currentSchema.transform { builder ->
            val queryTypeName = currentSchema.queryType?.name
            val mutationTypeName = currentSchema.mutationType?.name
            val subscriptionTypeName = currentSchema.subscriptionType?.name

            // --- FIXED: Safely check the type before setting root operation types ---
            if (queryTypeName != null && typeMap.containsKey(queryTypeName)) {
                val potentialQueryType = typeMap[queryTypeName]
                if (potentialQueryType is GraphQLObjectType) {
                    builder.query(potentialQueryType)
                }
            }
            if (mutationTypeName != null && typeMap.containsKey(mutationTypeName)) {
                val potentialMutationType = typeMap[mutationTypeName]
                if (potentialMutationType is GraphQLObjectType) {
                    builder.mutation(potentialMutationType)
                }
            }
            if (subscriptionTypeName != null && typeMap.containsKey(subscriptionTypeName)) {
                val potentialSubscriptionType = typeMap[subscriptionTypeName]
                if (potentialSubscriptionType is GraphQLObjectType) {
                    builder.subscription(potentialSubscriptionType)
                }
            }
            // --- END FIX ---

            val otherTypes = mutableSetOf<GraphQLType>()
            typeMap.values.forEach { type ->
                if (type.name != queryTypeName && type.name != mutationTypeName && type.name != subscriptionTypeName) {
                    otherTypes.add(type)
                }
            }
            otherTypes.add(GraphQLString); otherTypes.add(GraphQLInt); otherTypes.add(GraphQLFloat); otherTypes.add(GraphQLBoolean); otherTypes.add(GraphQLID)
            builder.clearAdditionalTypes().additionalTypes(otherTypes)
        }

        return Pair(newSchema, newTypesFound)
    }

    /**
     * Sends batched requests to discover all valid fields on the current type.
     * This version is adaptive: if the server rejects a request for being too large
     * (e.g., "Too many validation errors"), it splits the batch and retries.
     */
    private suspend fun probeValidFields(inputDocument: String): Set<String> {
        val validFields = mutableSetOf<String>()

        // Process the wordlist in initial chunks based on the configured bucket size
        wordlist.chunked(bucketSize).forEach { bucket ->
            yield() // Check for cancellation before processing a new major chunk
            validFields.addAll(probeBucket(bucket, inputDocument))
        }

        return validFields
    }

    /**
     * A recursive helper that probes a single bucket of words. If the bucket is too large
     * for the server's validation limit, it is split in half and re-probed.
     */
    private suspend fun probeBucket(bucket: List<String>, inputDocument: String): Set<String> {
        if (bucket.isEmpty()) {
            return emptySet()
        }

        yield() // Check for cancellation before sending a network request

        val document = inputDocument.replace("FUZZ", bucket.joinToString(" "))
        try {
            val response = Utils.sendGraphQLRequest(document, request!!)
            val errors = response.optJSONArray("errors")

            // Case 1: No errors. The entire bucket is valid.
            if (errors == null || errors.length() == 0) {
                return bucket.toSet()
            }

            val allErrorMessages = (0 until errors.length()).joinToString(separator = "\n") {
                errors.getJSONObject(it).optString("message", "")
            }

            // Case 2: The server's validation limit was reached.
            if (RegexStore.VALIDATION_ERROR_LIMIT.containsMatchIn(allErrorMessages)) {
                Logger.debug("Validation error limit reached. Splitting bucket of size ${bucket.size} and retrying.")
                val half = bucket.size / 2
                val firstHalfResult = probeBucket(bucket.take(half), inputDocument)
                val secondHalfResult = probeBucket(bucket.drop(half), inputDocument)
                return firstHalfResult + secondHalfResult // Combine results from both halves
            }

            // Case 3: Parent type is a scalar. Abort scanning for this type.
            if (RegexStore.NO_SUBFIELDS.find(allErrorMessages) != null) {
                Logger.debug("Detected scalar type from 'no subfields' error. Aborting field scan.")
                return emptySet()
            }

            val validFields = mutableSetOf<String>()

            // Case 4: High-confidence suggestions.
            val suggestions = RegexStore.getSuggestions(allErrorMessages, RegexStore.FIELD_SUGGESTIONS)
            if (suggestions.isNotEmpty()) {
                validFields.addAll(suggestions)
            }

            // Case 5: Fallback to process of elimination if no suggestions were found.
            if (suggestions.isEmpty()) {
                val invalidFieldsInBucket = mutableSetOf<String>()
                var recognizedErrorCount = 0

                (0 until errors.length()).forEach { i ->
                    val message = errors.getJSONObject(i).optString("message", "")
                    var isRecognized = false
                    for (regex in RegexStore.INVALID_FIELD) {
                        regex.findAll(message).forEach { match ->
                            match.groups["field"]?.value?.let {
                                if (it in bucket) {
                                    invalidFieldsInBucket.add(it)
                                    isRecognized = true
                                }
                            }
                        }
                    }
                    if (isRecognized) recognizedErrorCount++
                }

                if (recognizedErrorCount > 0 && recognizedErrorCount == errors.length()) {
                    val potentiallyValid = bucket.toMutableSet()
                    potentiallyValid.removeAll(invalidFieldsInBucket)
                    validFields.addAll(potentiallyValid)
                } else {
                    Logger.debug("Skipping bucket due to unrecognized or mixed errors. Messages: $allErrorMessages")
                }
            }
            return validFields

        } catch (e: Exception) {
            Logger.error("Error during field probing for document '$document': ${e.message}")
            return emptySet() // Return empty set on network or parsing error
        }
    }

    /**
     * Sends requests to discover all valid arguments for a given field.
     */
    private fun probeValidArguments(fieldQuery: String): Set<String> {
        val validArgs = mutableSetOf<String>()

        // Step 1: Probe for REQUIRED arguments by sending a query with no arguments.
        try {
            val responseNoArgs = Utils.sendGraphQLRequest(fieldQuery, request!!)
            responseNoArgs.optJSONArray("errors")?.forEach { error ->
                if (error !is org.json.JSONObject) return@forEach
                val message = error.optString("message", "")
                val match = RegexStore.MISSING_ARGUMENT.find(message)
                match?.groups?.get("argument")?.value?.let {
                    Logger.debug("Found required argument '$it' from MISSING_ARGUMENT error.")
                    validArgs.add(it)
                }
            }
        } catch (e: Exception) {
            Logger.debug("Error during missing argument probe (often expected): ${e.message}")
        }

        // Step 2: Probe for OPTIONAL arguments by triggering "Did you mean..." suggestions.
        try {
            // e.g., someField(____i_n_q_l____: "")
            val documentWithFakeArg = "$fieldQuery(${RegexStore.WRONG_ARG_EXAMPLE}: \"\")"
            val responseWithFakeArg = Utils.sendGraphQLRequest(documentWithFakeArg, request!!)

            // Combine all error messages for easier parsing.
            val allErrorMessages = responseWithFakeArg.optJSONArray("errors")?.let { errors ->
                (0 until errors.length()).joinToString(separator = "\n") {
                    errors.getJSONObject(it).optString("message", "")
                }
            } ?: ""

            if (allErrorMessages.isNotEmpty()) {
                val suggestions = RegexStore.getSuggestions(allErrorMessages, RegexStore.ARGUMENT_SUGGESTIONS)
                if (suggestions.isNotEmpty()) {
                    Logger.debug("Found suggested arguments: $suggestions")
                    validArgs.addAll(suggestions)
                }
            }
        } catch (e: Exception) {
            Logger.debug("Error during argument suggestion probe: ${e.message}")
        }

        return validArgs
    }


    /**
     * Probes the type of a specific argument by analyzing error messages.
     */
    private fun probeArgumentType(query: String, fieldName: String, argName: String): String {
        // Try with a string first
        var document = query.replace(RegexStore.WRONG_ARG_EXAMPLE, "\"test\"")
        var response = Utils.sendGraphQLRequest(document, request!!)
        var errors = response.optJSONArray("errors")

        if (errors == null) return GraphQLString.name

        for (i in 0 until errors.length()) {
            val message = errors.getJSONObject(i).optString("message", "")
            val match = RegexStore.WRONG_ARGUMENT_TYPE.find(message)
            if (match != null && match.groups["argument"]?.value == argName) {
                return match.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "") ?: GraphQLString.name
            }
            val missingArgMatch = RegexStore.MISSING_ARGUMENT.find(message)
            if (missingArgMatch != null && missingArgMatch.groups["argument"]?.value == argName) {
                return missingArgMatch.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "") ?: GraphQLString.name
            }
        }

        // Try with an integer if string failed
        document = query.replace(RegexStore.WRONG_ARG_EXAMPLE, "123")
        response = Utils.sendGraphQLRequest(document, request!!)
        errors = response.optJSONArray("errors")

        if (errors == null) return GraphQLInt.name

        for (i in 0 until errors.length()) {
            val message = errors.getJSONObject(i).optString("message", "")
            val match = RegexStore.WRONG_ARGUMENT_TYPE.find(message)
            if (match != null && match.groups["argument"]?.value == argName) {
                return match.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "") ?: GraphQLInt.name
            }
        }
        return "String" // Default fallback
    }
}