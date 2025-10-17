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
    // For finding the type name when a field is invalid
    val WRONG_TYPENAME = listOf(
        Regex("""Cannot query field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" on type "(?<typename>[_A-Za-z][_0-9A-Za-z]*)".(.*)"""),
        Regex("""Field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" is not defined by type "(?<typename>[_A-Za-z][_0-9A-Za-z]*)".(.*)"""),
        Regex("""Field '(?<field>[_A-Za-z][_0-9A-Za-z]*)' is not defined on type '(?<typename>[_A-Za-z][_0-9A-Za-z]*)'.(.*)"""),
        Regex("""Cannot query field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" on type "(?<typename>[_A-Za-z][_0-9A-Za-z]*)".$"""),
    )

    // For extracting field suggestions from error messages
    val FIELD_SUGGESTIONS = listOf(
        Regex("""Did you mean "(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)"\?"""),
        Regex("""Did you mean '(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)'\?"""),
    )

    // For finding the type of a field when a sub-selection is attempted on a scalar
    val NO_SUBFIELDS =
        Regex("""Field ["'](?<field>[_A-Za-z][_0-9A-Za-z]*)["'] must not have a selection since type ["']?(?<type>.*?)["']? has no subfields\.*""")


    // For finding the type of an argument when the wrong type is provided
    val WRONG_ARGUMENT_TYPE = Regex(
        """Argument "(?<argument>[_A-Za-z][_0-9A-Za-z]*)" has invalid value (?<value>.*). Expected type "(?<type>.*)","""
    )

    // For finding missing required arguments
    val MISSING_ARGUMENT =
        Regex("""Field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" argument "(?<argument>[_A-Za-z][_0-9A-Za-z]*)" of type "(?<type>.*)" is required but not provided.""")

    // For extracting argument suggestions
    val ARGUMENT_SUGGESTIONS = listOf(
        Regex("""Unknown argument "(?<argument>[_A-Za-z][_0-9A-Za-z]*)" on field "(?<field>[_A-Za-z][_0-9A-Za-z]*)" of type "(?<type>[_A-Za-z][_0-9A-Za-z]*)". Did you mean "(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)"\?"""),
        Regex("""Unknown argument '(?<argument>[_A-Za-z][_0-9A-Za-z]*)' on field '(?<field>[_A-Za-z][_0-9A-Za-z]*)'. Did you mean '(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)'\?"""),
    )

    // A fake field name used to trigger type name errors
    const val WRONG_FIELD_EXAMPLE = "____i_n_q_l____"
    const val WRONG_ARG_EXAMPLE = "____i_n_q_l____"

    fun getSuggestions(errorMessage: String, regexList: List<Regex>): List<String> {
        return regexList.flatMap { regex ->
            regex.findAll(errorMessage).mapNotNull { it.groups["suggestion"]?.value }
        }.distinct()
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
    private var depthLimit: Int = 3

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
        depthLimit = Config.getInstance().getInt("bruteforcer.depth_limit") ?: 3

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

            val currentDepth = pathToType.size - 1
            if (currentDepth > depthLimit) {
                Logger.debug("Skipping type '$currentTypeName' as its depth ($currentDepth) exceeds the configured limit of $depthLimit.")
                scannedTypes.add(currentTypeName) // Mark as "scanned" to prevent re-adding
                continue
            }


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

            for (i in 0 until errors.length()) {
                val message = errors.getJSONObject(i).optString("message", "")

                if (message.contains("Schema is not configured for")) return null

                // CHECK FOR SCALAR TYPES FIRST
                val noSubfieldsMatch = RegexStore.NO_SUBFIELDS.find(message)
                if (noSubfieldsMatch != null) {
                    return noSubfieldsMatch.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "")
                }

                for (regex in RegexStore.WRONG_TYPENAME) {
                    val match = regex.find(message)
                    if (match != null) {
                        return match.groups["typename"]?.value?.replace(Regex("[\\[\\]!]"), "")
                    }
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
            if (queryTypeName != null && typeMap.containsKey(queryTypeName)) {
                builder.query(typeMap[queryTypeName] as GraphQLObjectType)
            }
            if (mutationTypeName != null && typeMap.containsKey(mutationTypeName)) {
                builder.mutation(typeMap[mutationTypeName] as GraphQLObjectType)
            }
            if (subscriptionTypeName != null && typeMap.containsKey(subscriptionTypeName)) {
                builder.subscription(typeMap[subscriptionTypeName] as GraphQLObjectType)
            }
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
     * This version is hardened against inconclusive server responses. It will only
     * determine fields based on three conditions:
     * 1. A successful response with no errors (all fields in the bucket are valid).
     * 2. High-confidence "Did you mean..." suggestions from the server.
     * 3. A response containing *only* "field is not defined" errors, allowing for a safe
     * process of elimination.
     * Any other error, like a "Syntax Error", will cause the bucket to be safely ignored.
     */
    private suspend fun probeValidFields(inputDocument: String): Set<String> {
        val validFields = mutableSetOf<String>()

        // Use a labeled 'run' block to allow breaking out of the outer .forEach loop
        run loop@{
            wordlist.chunked(bucketSize).forEach { bucket ->
                yield()

                val document = inputDocument.replace("FUZZ", bucket.joinToString(" "))
                try {
                    val response = Utils.sendGraphQLRequest(document, request!!)
                    val errors = response.optJSONArray("errors")

                    // Case 1: No errors. The entire bucket is valid.
                    if (errors == null || errors.length() == 0) {
                        validFields.addAll(bucket)
                        return@forEach // Continue to the next bucket
                    }

                    var hasSuggestions = false
                    var hasRecognizedFieldErrors = false
                    val fieldsInSuggestions = mutableSetOf<String>()
                    val fieldsInErrors = mutableSetOf<String>()

                    for (i in 0 until errors.length()) {
                        val message = errors.getJSONObject(i).optString("message", "")

                        // If the server says the parent has no subfields, it's a scalar. Abort everything.
                        if (RegexStore.NO_SUBFIELDS.find(message) != null) {
                            Logger.debug("Detected scalar type from 'no subfields' error. Aborting field scan.")
                            validFields.clear()
                            return@loop // Exit the entire 'run' block
                        }

                        // Collect high-confidence suggestions.
                        val suggestions = RegexStore.getSuggestions(message, RegexStore.FIELD_SUGGESTIONS)
                        if (suggestions.isNotEmpty()) {
                            hasSuggestions = true
                            fieldsInSuggestions.addAll(suggestions)
                        }

                        // Collect explicit "field not defined" errors.
                        for (regex in RegexStore.WRONG_TYPENAME) {
                            val match = regex.find(message)
                            match?.groups?.get("field")?.value?.let { invalidField ->
                                fieldsInErrors.add(invalidField)
                                hasRecognizedFieldErrors = true
                            }
                        }
                    }

                    // --- Decision Logic ---

                    if (hasSuggestions) {
                        // High-confidence suggestions are the most reliable result.
                        validFields.addAll(fieldsInSuggestions)
                    } else if (hasRecognizedFieldErrors) {
                        // If we only got "field not defined" errors, we can trust the process of elimination.
                        val potentiallyValid = bucket.toMutableSet()
                        potentiallyValid.removeAll(fieldsInErrors)
                        validFields.addAll(potentiallyValid)
                    } else {
                        // If we received errors, but none of them were recognized validation errors
                        // (e.g., it was a "Syntax Error"), the result for this bucket is inconclusive.
                        // We cannot safely assume any fields are valid, so we do nothing.
                        Logger.debug("Skipping bucket due to unrecognized or generic errors (e.g., Syntax Error).")
                    }

                } catch(e: Exception) {
                    Logger.error("Error during field probing for document '$document': ${e.message}")
                }
            }
        }
        return validFields
    }

    /**
     * Sends requests to discover all valid arguments for a given field.
     */
    private fun probeValidArguments(fieldQuery: String): Set<String> {
        val validArgs = mutableSetOf<String>()

        // Step 1: Probe for REQUIRED arguments by sending a query with no arguments.
        // The server will complain about any missing required arguments.
        try {
            val documentNoArgs = fieldQuery // Query the field directly, e.g., "location"
            val responseNoArgs = Utils.sendGraphQLRequest(documentNoArgs, request!!)
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
            Logger.debug("Error during missing argument probe (this is often expected): ${e.message}")
        }

        // Step 2: Probe for OPTIONAL arguments by triggering "Did you mean..." suggestions.
        try {
            val documentWithFakeArg = "$fieldQuery(${RegexStore.WRONG_ARG_EXAMPLE}: \"\")"
            val responseWithFakeArg = Utils.sendGraphQLRequest(documentWithFakeArg, request!!)
            responseWithFakeArg.optJSONArray("errors")?.forEach { error ->
                if (error !is org.json.JSONObject) return@forEach
                val message = error.optString("message", "")
                validArgs.addAll(RegexStore.getSuggestions(message, RegexStore.ARGUMENT_SUGGESTIONS))
            }
        } catch (e: Exception) {
            Logger.debug("Error during argument suggestion probe: ${e.message}")
        }

        return validArgs
    }


    /**
     * Probes the type of a specific argument by systematically trying different
     * JSON value types and analyzing the resulting error messages. This method
     * is more exhaustive and aligns with the original Clairvoyance strategy.
     */
    private fun probeArgumentType(query: String, fieldName: String, argName: String): String {
        // A list of probes, mapping a potential GraphQL type to a value string for the query.
        val probes = listOf(
            // String is the most common type, so we try it first.
            GraphQLString.name to "\"test\"",
            // Integer is next.
            GraphQLInt.name to "123",
            // Boolean.
            GraphQLBoolean.name to "true",
            // Float.
            GraphQLFloat.name to "1.23",
            // An empty object literal to test for InputObject types.
            "Object" to "{}"
        )

        for ((assumedType, probeValue) in probes) {
            val document = query.replace(RegexStore.WRONG_ARG_EXAMPLE, probeValue)
            try {
                val response = Utils.sendGraphQLRequest(document, request!!)
                val errors = response.optJSONArray("errors")

                // Case 1: The request succeeded without errors.
                // This means our probe value was valid. We can assume the type we just tried is correct.
                // Note: If the "Object" probe ({}) succeeds, we cannot know the exact InputObject name,
                // so we fall through and hope a later probe with an invalid type will reveal the name.
                // For primitives, however, this is a reliable indicator.
                if (errors == null || errors.length() == 0) {
                    if (assumedType != "Object") {
                        Logger.debug("Argument '$argName' accepted probe for type '$assumedType'.")
                        return assumedType
                    }
                } else {
                    // Case 2: The request failed. This is good! The error message likely tells us the exact type.
                    for (i in 0 until errors.length()) {
                        val message = errors.getJSONObject(i).optString("message", "")

                        // The most reliable error: "Argument 'x' has invalid value. Expected type 'Y'."
                        val match = RegexStore.WRONG_ARGUMENT_TYPE.find(message)
                        if (match != null && match.groups["argument"]?.value == argName) {
                            val discoveredType = match.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "")
                            if (discoveredType != null) {
                                Logger.debug("Discovered argument type '$discoveredType' for '$argName' from WRONG_ARGUMENT_TYPE error.")
                                return discoveredType
                            }
                        }

                        // A secondary check for missing argument errors, which can also contain the type.
                        val missingArgMatch = RegexStore.MISSING_ARGUMENT.find(message)
                        if (missingArgMatch != null && missingArgMatch.groups["argument"]?.value == argName) {
                            val discoveredType = missingArgMatch.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "")
                            if (discoveredType != null) {
                                Logger.debug("Discovered argument type '$discoveredType' for '$argName' from MISSING_ARGUMENT error.")
                                return discoveredType
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Logger.error("Exception during argument type probe for '$argName' with value '$probeValue': ${e.message}")
                // Continue to the next probe.
            }
        }

        // If all probes fail to determine the type, fallback to String as a safe default.
        Logger.debug("Could not determine type for argument '$argName'. Defaulting to String.")
        return GraphQLString.name
    }

}