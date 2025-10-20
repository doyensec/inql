package inql.bruteforcer

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.Scalars.*
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
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlin.Pair

/**
 * Main class for bruteforcing the GraphQL schema.
 * This class orchestrates the entire process of schema discovery, from finding root types
 * to recursively scanning each object type for its fields and arguments.
 */
class Bruteforcer(private val inql: InQL) {
    private var request: HttpRequest? = null
    private lateinit var graphQLClient: ThrottledClient
    private var bucketSize: Int = 64
    private var wordlist: List<String> = emptyList()
    private var argumentWordlist: List<String> = emptyList()
    private var depthLimit: Int = 3
    private var concurrencyLimit: Int = 8
    private var bruteforceArguments: Boolean = true

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
        depthLimit = Config.getInstance().getInt("bruteforcer.depth_limit") ?: 2
        concurrencyLimit = Config.getInstance().getInt("bruteforcer.concurrency_limit") ?: 8
        bruteforceArguments = Config.getInstance().getBoolean("bruteforcer.bruteforce_arguments") ?: true

        graphQLClient = ThrottledClient(req)

        val wordlistFile = Config.getInstance()
            .getString("bruteforcer.custom_wordlist")
            ?.takeIf { it.isNotEmpty() }
            ?: "wordlist.txt"

        val argWordlistFile = Config.getInstance()
            .getString("bruteforcer.custom_arg_wordlist")
            ?.takeIf { it.isNotEmpty() }
            ?: "arg_wordlist.txt"

        wordlist = loadWordlist(wordlistFile)
        argumentWordlist = loadWordlist(argWordlistFile)

        val schema = run()
        return GraphQLSchemaToSDL.schemaToSDL(schema)
    }

    /**
     * Loads and filters the wordlist from a file.
     */
    private fun loadWordlist(wordlistFile: String): List<String> {
        val fileContent = when (wordlistFile) {
            "wordlist.txt" -> ResourceFileReader.readFile(wordlistFile)
            "arg_wordlist.txt" -> ResourceFileReader.readFile(wordlistFile)
            else -> File(wordlistFile).takeIf { it.exists() }?.readText()
        } ?: throw EmptyOrIncorrectWordlistException("Wordlist file not found: $wordlistFile")

        if (fileContent.isEmpty()) {
            throw EmptyOrIncorrectWordlistException("$wordlistFile is empty")
        }

        val tmpWordlist = fileContent.lineSequence()
            .filter { it.isNotBlank() && NAME_REGEX.matches(it) }
            .distinct()
            .toList()

        if (tmpWordlist.isEmpty()) {
            throw EmptyOrIncorrectWordlistException("No valid words in the $wordlistFile")
        }

        return tmpWordlist
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

            val currentType = schema.getType(currentTypeName)

            if (currentType == null) {
                Logger.error("Type '$currentTypeName' not found in schema. Skipping.")
                scannedTypes.add(currentTypeName)
                continue
            }

            val result = when (currentType) {
                is GraphQLObjectType -> {
                    Logger.debug("Scanning OBJECT type: $currentTypeName")
                    val pathToType = findPathToType(schema, currentTypeName)
                    val currentDepth = pathToType.size - 1
                    if (currentDepth > depthLimit) {
                        Logger.debug("Skipping type '$currentTypeName' as its depth ($currentDepth) exceeds the configured limit of $depthLimit.")
                        scannedTypes.add(currentTypeName) // Mark as "scanned" to prevent re-adding
                        continue
                    }

                    val scanQuery = convertPathToQuery(pathToType, schema)
                    scanType(scanQuery, currentTypeName, schema)
                }
                is GraphQLInputObjectType -> {
                    scanInputObjectType(currentTypeName, schema)
                }
                else -> {
                    Logger.debug("Skipping non-scannable type '$currentTypeName' (${currentType::class.simpleName}).")
                    Pair(schema, emptySet()) // No changes, no new types
                }
            }



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
    private suspend fun fetchRootTypeNames(): RootTypeNames {
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

        val placeholderField = GraphQLFieldDefinition.newFieldDefinition()
            .name("_inql_placeholder")
            .type(GraphQLString)
            .build()

        rootNames.queryType?.let {
            val type = GraphQLObjectType.newObject()
                .name(it)
                .field(placeholderField)
                .build()
            schemaBuilder.query(type)
        }
        rootNames.mutationType?.let {
            val type = GraphQLObjectType.newObject()
                .name(it)
                .field(placeholderField)
                .build()
            schemaBuilder.mutation(type)
        }
        rootNames.subscriptionType?.let {
            val type = GraphQLObjectType.newObject()
                .name(it)
                .field(placeholderField)
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
    private suspend fun probeTypename(inputDocument: String): String? {
        val document = inputDocument.replace("FUZZ", RegexStore.WRONG_FIELD_EXAMPLE)
        try {
            val response = graphQLClient.send(document)
            val errors = response.optJSONArray("errors") ?: return null

            for (i in 0 until errors.length()) {
                val message = errors.getJSONObject(i).optString("message", "")

                if (message.contains("Schema is not configured for")) return null

                val selectionOnScalarMatch = RegexStore.SELECTION_ON_SCALAR.find(message)
                if (selectionOnScalarMatch != null) {
                    return selectionOnScalarMatch.groups["type"]?.value
                }

                val missingSubfieldsMatch = RegexStore.MISSING_SUBFIELDS.find(message)
                if (missingSubfieldsMatch != null) {
                    return missingSubfieldsMatch.groups["type"]?.value
                }

                val noSubfieldsMatch = RegexStore.NO_SUBFIELDS.find(message)
                if (noSubfieldsMatch != null) {
                    return noSubfieldsMatch.groups["type"]?.value
                }

                for (regex in RegexStore.WRONG_TYPENAME) {
                    val match = regex.find(message)
                    if (match != null) {
                        return match.groups["typename"]?.value
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

    private data class FieldScanResult(
        val fieldDefinition: GraphQLFieldDefinition,
        val discoveredOutputTypes: Set<String>,
        val discoveredInputTypes: Set<String>
    )

    /**
     * Parses a type string like "[String!]!" into a nested GraphQLType object.
     */
    private fun parseTypeString(typeString: String): GraphQLType {
        var remainingType = typeString.trim()
        var type: GraphQLType

        // 1. Check for Non-Null at the end
        if (remainingType.endsWith('!')) {
            remainingType = remainingType.dropLast(1)
            // Recursively parse the inner type and wrap it
            type = GraphQLNonNull(parseTypeString(remainingType))
        }
        // 2. Check for List
        else if (remainingType.startsWith('[') && remainingType.endsWith(']')) {
            remainingType = remainingType.substring(1, remainingType.length - 1)
            // Recursively parse the inner type and wrap it
            type = GraphQLList(parseTypeString(remainingType))
        }
        // 3. Base case: It's a named type
        else {
            type = GraphQLTypeReference(remainingType)
        }
        return type
    }

    /**
     * Performs the core scan on a single type to find its fields, their types, and arguments.
     * This version intelligently reclassifies objects with no discovered fields as custom scalars.
     */
    private suspend fun scanType(scanQuery: String, typeName: String, schema: GraphQLSchema): Pair<GraphQLSchema, Set<String>> = coroutineScope {
        val validFields = probeValidFields(scanQuery)
        val newTypesFound = mutableSetOf<String>()
        val currentSchema = schema
        val typeMap = currentSchema.typeMap.toMutableMap()
        val semaphore = Semaphore(concurrencyLimit)

        if (validFields.isEmpty()) {
            Logger.debug("No fields found for '$typeName'. Reclassifying as a custom scalar.")

            // Define a generic Coercing implementation for discovered scalars.
            val passThroughCoercing = object : Coercing<Any, Any> {
                override fun serialize(dataFetcherResult: Any): Any = dataFetcherResult
                override fun parseValue(input: Any): Any = input
            }

            val newScalar = GraphQLScalarType.newScalar()
                .name(typeName)
                .coercing(passThroughCoercing)
                .build()

            typeMap[typeName] = newScalar
        } else {
            // Launch parallel jobs to scan each field for its type and arguments
            val fieldScanJobs = validFields.map { fieldName ->
                async {
                    semaphore.withPermit {
                        Logger.debug("Found field: $fieldName on type $typeName")
                        // MODIFICATION: Create separate sets for input and output types
                        val discoveredOutputTypesForField = mutableSetOf<String>()
                        val discoveredInputTypesForField = mutableSetOf<String>()

                        // Probe field type
                        val fieldQuery = scanQuery.replace("FUZZ", "$fieldName { ${RegexStore.WRONG_FIELD_EXAMPLE} }")
                        val fieldTypeName = probeTypename(fieldQuery) ?: "String"
                        // MODIFICATION: Add the BASE name of the type to the output set
                        val baseFieldTypeName = fieldTypeName.replace(Regex("[\\[\\]!]"), "")
                        discoveredOutputTypesForField.add(baseFieldTypeName)


                        // Probe arguments
                        val arguments = probeValidArguments(scanQuery, fieldName)
                        val fieldDefBuilder = GraphQLFieldDefinition.newFieldDefinition()
                            .name(fieldName)
                            .type(parseTypeString(fieldTypeName) as GraphQLOutputType)

                        for (argName in arguments) {
                            val argQuery =
                                scanQuery.replace("FUZZ", "$fieldName($argName: ${RegexStore.WRONG_ARG_EXAMPLE}) { __typename }")
                            val argTypeName = probeArgumentType(argQuery, fieldName, argName)
                            val baseTypeName = argTypeName.replace(Regex("[\\[\\]!]"), "")
                            // MODIFICATION: Add the argument's base type to the INPUT set
                            discoveredInputTypesForField.add(baseTypeName)

                            fieldDefBuilder.argument(
                                GraphQLArgument.newArgument()
                                    .name(argName)
                                    .type(parseTypeString(argTypeName) as GraphQLInputType) // This cast is still needed for the compiler
                                    .build()
                            )
                        }
                        // MODIFICATION: Return the new FieldScanResult with both sets
                        FieldScanResult(fieldDefBuilder.build(), discoveredOutputTypesForField, discoveredInputTypesForField)
                    }
                }
            }

            // Build the final object type from the parallel results
            val typeBuilder = GraphQLObjectType.newObject(currentSchema.getObjectType(typeName)).clearFields()
            // MODIFICATION: Collect types into separate sets
            val allDiscoveredOutputTypes = mutableSetOf<String>()
            val allDiscoveredInputTypes = mutableSetOf<String>()

            fieldScanJobs.forEach { job ->
                val result = job.await()
                typeBuilder.field(result.fieldDefinition)
                allDiscoveredOutputTypes.addAll(result.discoveredOutputTypes)
                allDiscoveredInputTypes.addAll(result.discoveredInputTypes)
            }
            typeMap[typeName] = typeBuilder.build()

            // MODIFICATION: Use the collected sets to drive placeholder creation
            newTypesFound.addAll(allDiscoveredOutputTypes)
            newTypesFound.addAll(allDiscoveredInputTypes)

            // Add placeholders for any newly discovered types that have not been scanned yet.
            newTypesFound.forEach {
                if (it !in typeMap && it !in BUILT_IN_SCALARS) {
                    // NEW LOGIC: Check if the type was discovered as an input type
                    if (it in allDiscoveredInputTypes) {
                        // Create a GraphQLInputObjectType placeholder
                        val placeholderField = GraphQLInputObjectField.newInputObjectField()
                            .name("_inql_placeholder")
                            .type(GraphQLString)
                            .build()
                        typeMap[it] = GraphQLInputObjectType.newInputObject().name(it).field(placeholderField).build()
                    } else {
                        // Otherwise, create a regular GraphQLObjectType placeholder
                        val placeholderField = GraphQLFieldDefinition.newFieldDefinition()
                            .name("_inql_placeholder")
                            .type(GraphQLString)
                            .build()
                        typeMap[it] = GraphQLObjectType.newObject().name(it).field(placeholderField).build()
                    }
                }
            }
        }

        // Rebuild the schema with our updated typemap.
        val newSchema = currentSchema.transform { builder ->
            val queryTypeName = currentSchema.queryType?.name
            val mutationTypeName = currentSchema.mutationType?.name
            val subscriptionTypeName = currentSchema.subscriptionType?.name

            if (queryTypeName != null && typeMap.containsKey(queryTypeName)) {
                val type = typeMap[queryTypeName]
                // Only set if it's an ObjectType
                if (type is GraphQLObjectType) {
                    builder.query(type)
                }
            }
            if (mutationTypeName != null && typeMap.containsKey(mutationTypeName)) {
                val type = typeMap[mutationTypeName]
                // Only set if it's an ObjectType
                if (type is GraphQLObjectType) {
                    builder.mutation(type)
                }
            }
            if (subscriptionTypeName != null && typeMap.containsKey(subscriptionTypeName)) {
                val type = typeMap[subscriptionTypeName]
                // Only set if it's an ObjectType
                if (type is GraphQLObjectType) {
                    builder.subscription(type)
                }
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

        return@coroutineScope Pair(newSchema, newTypesFound)
    }


    /**
     * Sends batched requests in parallel to discover all valid fields on the current type.
     * This version is hardened against inconclusive server responses.
     */
    private suspend fun probeValidFields(inputDocument: String): Set<String> = coroutineScope {
        val allValidFields = mutableSetOf<String>()
        val semaphore = Semaphore(concurrencyLimit)

        val deferredResults = wordlist.chunked(bucketSize).map { bucket ->
            async {
                semaphore.withPermit<Set<String>?> {
                    val document = inputDocument.replace("FUZZ", bucket.joinToString(" "))
                    try {
                        val response = graphQLClient.send(document)
                        val errors = response.optJSONArray("errors")

                        if (errors == null || errors.length() == 0) {
                            return@withPermit bucket.toSet() // The entire bucket is valid.
                        }

                        if (errors.toString().contains("has no subfields")) {
                            Logger.debug("Detected scalar type from 'no subfields' error. Aborting field scan.")
                            return@withPermit null // Signal for scalar type
                        }

                        val fieldsInSuggestions = mutableSetOf<String>()
                        val fieldsInErrors = mutableSetOf<String>()
                        var hasRecognizedErrors = false

                        for (i in 0 until errors.length()) {
                            val message = errors.getJSONObject(i).optString("message", "")
                            fieldsInSuggestions.addAll(RegexStore.getSuggestions(message, RegexStore.FIELD_SUGGESTIONS))
                            for (regex in RegexStore.WRONG_TYPENAME) {
                                regex.find(message)?.groups?.get("field")?.value?.let { invalidField ->
                                    fieldsInErrors.add(invalidField)
                                    hasRecognizedErrors = true
                                }
                            }
                        }

                        // --- Corrected Hybrid Decision Logic ---
                        if (fieldsInSuggestions.isNotEmpty() || hasRecognizedErrors) {
                            val potentiallyValid = bucket.toMutableSet()
                            // 1. Subtract all fields that we know are invalid.
                            potentiallyValid.removeAll(fieldsInErrors)
                            // 2. Add all high-confidence suggestions (which might not have been in the bucket).
                            potentiallyValid.addAll(fieldsInSuggestions)

                            return@withPermit potentiallyValid
                        } else {
                            return@withPermit emptySet()
                        }
                    } catch (e: Exception) {
                        Logger.error("Error during field probing for document '$document': ${e.message}")
                        return@withPermit emptySet()
                    }
                }
            }
        }

        deferredResults.forEach { deferred ->
            val result = deferred.await()
            if (result == null) {
                allValidFields.clear()
                return@coroutineScope allValidFields
            }
            allValidFields.addAll(result)
        }
        return@coroutineScope allValidFields
    }

    /**
     * Finds a path to a field that uses the given InputObjectType name in one of its arguments.
     * Returns a list representing the path, e.g., ["Mutation", "insert_users", "objects_arg"].
     */
    private fun findPathToFieldUsingInput(schema: GraphQLSchema, targetInputTypeName: String): List<String>? {
        val roots = listOfNotNull(schema.queryType, schema.mutationType, schema.subscriptionType)
        val queue: Queue<List<String>> = LinkedList()
        roots.forEach { queue.add(listOf(it.name)) }

        while (queue.isNotEmpty()) {
            val path = queue.poll()

            // Resolve the current type at the end of the path
            var currentType: GraphQLType = schema.getType(path.first()) as GraphQLType
            for (fieldName in path.drop(1)) {
                val container = GraphQLTypeUtil.unwrapAll(currentType) as? GraphQLFieldsContainer ?: break
                currentType = container.getFieldDefinition(fieldName)?.type ?: break
            }

            val currentFieldsContainer = GraphQLTypeUtil.unwrapAll(currentType) as? GraphQLFieldsContainer ?: continue

            for (field in currentFieldsContainer.fieldDefinitions) {
                for (argument in field.arguments) {
                    val argumentTypeName = GraphQLTypeUtil.unwrapAll(argument.type).name
                    if (argumentTypeName == targetInputTypeName) {
                        // Found it! Return the path to the field, plus the argument name.
                        return path + field.name + argument.name
                    }
                }

                // If the field returns another object type, add it to the queue to scan its fields
                if (GraphQLTypeUtil.unwrapAll(field.type) is GraphQLObjectType) {
                    queue.add(path + field.name)
                }
            }
        }
        return null // Path not found
    }

    /**
     * Scans a GraphQLInputObjectType to discover its fields.
     */
    private suspend fun scanInputObjectType(typeName: String, schema: GraphQLSchema): Pair<GraphQLSchema, Set<String>> {
        Logger.debug("Scanning INPUT type: $typeName")
        val path = findPathToFieldUsingInput(schema, typeName)
            ?: throw IllegalStateException("Could not find a field using input type $typeName")

        val operationName = if (path.first() == schema.mutationType?.name) "mutation" else "query"
        val fieldPath = path.drop(1).dropLast(1)
        val argumentName = path.last()

        var queryBody = ""
        var currentPathType: GraphQLType = schema.getType(path.first()) as GraphQLType

        fieldPath.forEach { fieldName ->
            val container = GraphQLTypeUtil.unwrapAll(currentPathType) as GraphQLFieldsContainer
            val fieldDef = container.getFieldDefinition(fieldName)!!
            currentPathType = fieldDef.type
            queryBody += "$fieldName { "
        }

        val lastField = fieldPath.lastOrNull() ?: path.first()
        val probeQuery = "$queryBody $lastField($argumentName: { FUZZ }) { __typename } ${"}".repeat(fieldPath.size)}"
        val finalQuery = "$operationName { $probeQuery }"

        val validFields = probeValidFieldsForInputObject(finalQuery)

        val typeMap = schema.typeMap.toMutableMap()
        val typeBuilder = GraphQLInputObjectType.newInputObject(schema.getType(typeName) as GraphQLInputObjectType).clearFields()

        validFields.forEach { fieldName ->
            // For simplicity, we default discovered input fields to String.
            typeBuilder.field(
                GraphQLInputObjectField.newInputObjectField()
                    .name(fieldName)
                    .type(GraphQLString)
                    .build()
            )
        }

        // Replace the old type definition with our newly built one in the map
        typeMap[typeName] = typeBuilder.build()

        // --- START: CORRECTED SCHEMA TRANSFORMATION ---
        // This logic correctly rebuilds the schema, preventing the redefinition error.
        val newSchema = schema.transform { builder ->
            val queryTypeName = schema.queryType?.name
            val mutationTypeName = schema.mutationType?.name
            val subscriptionTypeName = schema.subscriptionType?.name

            // Explicitly set the root types, using the versions from our map
            if (queryTypeName != null && typeMap.containsKey(queryTypeName)) {
                builder.query(typeMap[queryTypeName] as GraphQLObjectType)
            }
            if (mutationTypeName != null && typeMap.containsKey(mutationTypeName)) {
                builder.mutation(typeMap[mutationTypeName] as GraphQLObjectType)
            }
            if (subscriptionTypeName != null && typeMap.containsKey(subscriptionTypeName)) {
                builder.subscription(typeMap[subscriptionTypeName] as GraphQLObjectType)
            }

            // Collect all other types, including our updated input object type
            val otherTypes = mutableSetOf<GraphQLType>()
            typeMap.values.forEach { type ->
                if (type.name != queryTypeName && type.name != mutationTypeName && type.name != subscriptionTypeName) {
                    otherTypes.add(type)
                }
            }

            // Re-add built-in scalars to ensure they're present
            otherTypes.addAll(BUILT_IN_SCALARS.mapNotNull { schema.getType(it) })

            builder.clearAdditionalTypes().additionalTypes(otherTypes)
        }
        // --- END: CORRECTED SCHEMA TRANSFORMATION ---

        return Pair(newSchema, emptySet<String>()) // We don't discover new types this way for now
    }
    /**
     * A specialized version of probeValidFields for input objects.
     */
    private suspend fun probeValidFieldsForInputObject(inputDocument: String): Set<String> = coroutineScope {
        // This logic is very similar to probeValidFields but looks for input-specific errors
        val allValidFields = mutableSetOf<String>()
        val semaphore = Semaphore(concurrencyLimit)

        val deferredResults = wordlist.chunked(bucketSize).map { bucket ->
            async {
                semaphore.withPermit<Set<String>> {
                    val document = inputDocument.replace("FUZZ", bucket.joinToString(", ") { "$it: null" })
                    try {
                        val response = graphQLClient.send(document)
                        val errors = response.optJSONArray("errors") ?: return@withPermit bucket.toSet()

                        val fieldsInErrors = mutableSetOf<String>()
                        errors.forEach { error ->
                            if (error !is org.json.JSONObject) return@forEach
                            val message = error.optString("message", "")
                            RegexStore.UNKNOWN_INPUT_FIELD.find(message)?.groups?.get("field")?.value?.let {
                                fieldsInErrors.add(it)
                            }
                        }

                        return@withPermit bucket.toSet().subtract(fieldsInErrors)

                    } catch (e: Exception) {
                        return@withPermit emptySet()
                    }
                }
            }
        }
        deferredResults.forEach { allValidFields.addAll(it.await()) }
        return@coroutineScope allValidFields
    }


    /**
     * Sends requests to discover all valid arguments for a given field.
     * This version is refactored to construct syntactically correct queries
     * for nested fields, preventing "Syntax Error" false positives.
     */
    private suspend fun probeValidArguments(scanQuery: String, fieldName: String): Set<String> = coroutineScope {
        val validArgs = mutableSetOf<String>()

        // Step 1: Probe for REQUIRED arguments.
        try {
            val documentNoArgs = scanQuery.replace("FUZZ", "$fieldName { __typename }")
            val responseNoArgs = graphQLClient.send(documentNoArgs)
            responseNoArgs.optJSONArray("errors")?.forEach { error ->
                if (error !is org.json.JSONObject) return@forEach
                val message = error.optString("message", "")

                // Check if the field itself is invalid. If so, abort this whole function.
                for (regex in RegexStore.WRONG_TYPENAME) {
                    val match = regex.find(message)
                    if (match != null && match.groups["field"]?.value == fieldName) {
                        Logger.debug("Field '$fieldName' reported as non-existent during argument probe (Step 1). Aborting argument scan.")
                        return@coroutineScope emptySet() // Exit probeValidArguments
                    }
                }

                RegexStore.MISSING_ARGUMENT.find(message)?.let { match ->
                    val errorField = match.groups["field"]?.value
                    val errorArg = match.groups["argument"]?.value

                    // This check prevents the race condition
                    if (errorField == fieldName && errorArg != null) {
                        Logger.debug("Found required argument '$errorArg' on '$fieldName' from MISSING_ARGUMENT error.")
                        validArgs.add(errorArg)
                    }
                }
            }
        } catch (e: Exception) {
            Logger.debug("Error during missing argument probe for '$fieldName': ${e.message}")
        }

        // Step 2: Probe for OPTIONAL arguments using suggestions.
        var foundArgsViaSuggestions = false
        try {
            val documentWithFakeArg = scanQuery.replace("FUZZ", "$fieldName(${RegexStore.WRONG_ARG_EXAMPLE}: null) { __typename }")
            val responseWithFakeArg = graphQLClient.send(documentWithFakeArg)
            responseWithFakeArg.optJSONArray("errors")?.forEach { error ->
                if (error !is org.json.JSONObject) return@forEach
                val message = error.optString("message", "")

                for (regex in RegexStore.WRONG_TYPENAME) {
                    val match = regex.find(message)
                    if (match != null && match.groups["field"]?.value == fieldName) {
                        Logger.debug("Field '$fieldName' reported as non-existent during argument probe (Step 2). Aborting argument scan.")
                        return@coroutineScope emptySet() // Exit probeValidArguments
                    }
                }

                val suggestions = RegexStore.ARGUMENT_SUGGESTIONS.flatMap { regex ->
                    regex.findAll(message).mapNotNull { match ->
                        // Also validate the field name for suggestions
                        if (match.groups["field"]?.value == fieldName) {
                            match.groups["suggestion"]?.value
                        } else {
                            null
                        }
                    }
                }.distinct()

                if (suggestions.isNotEmpty()) {
                    foundArgsViaSuggestions = true
                    validArgs.addAll(suggestions)
                }
            }
        } catch (e: Exception) {
            Logger.debug("Error during argument suggestion probe for '$fieldName': ${e.message}")
        }

        // Step 3: FALLBACK - If suggestions failed, brute-force from the wordlist.
        if (!foundArgsViaSuggestions && bruteforceArguments) {
            Logger.debug("No argument suggestions found. Falling back to brute-force for field '$fieldName'")
            val semaphore = Semaphore(concurrencyLimit)
            val deferredResults = argumentWordlist.chunked(bucketSize).map { bucket ->
                async {
                    semaphore.withPermit {
                        val bucketValidArgs = mutableSetOf<String>()
                        for (argCandidate in bucket) {
                            if (argCandidate in validArgs) continue

                            val document = scanQuery.replace("FUZZ", "$fieldName($argCandidate: null) { __typename }")
                            try {
                                val response = graphQLClient.send(document)
                                val errors = response.optJSONArray("errors") ?: continue

                                var isFieldItselfInvalid = false
                                var isCandidateExplicitlyUnknown = false
                                for (i in 0 until errors.length()) {
                                    val errorMessage = errors.getJSONObject(i).optString("message", "")

                                    for (regex in RegexStore.WRONG_TYPENAME) {
                                        val match = regex.find(errorMessage)
                                        if (match != null && match.groups["field"]?.value == fieldName) {
                                            isFieldItselfInvalid = true
                                            break
                                        }
                                    }
                                    if (isFieldItselfInvalid) break // Stop checking other errors

                                    // Check if THIS candidate is explicitly unknown.
                                    for (regex in RegexStore.UNKNOWN_ARGUMENT) {
                                        val unknownArgMatch = regex.find(errorMessage)
                                        if (unknownArgMatch != null && unknownArgMatch.groups["argument"]?.value == argCandidate) {
                                            isCandidateExplicitlyUnknown = true
                                            break
                                        }
                                    }
                                }

                                if (isFieldItselfInvalid) {
                                    Logger.debug("Field '$fieldName' reported as non-existent during brute-force. Stopping scan for this bucket.")
                                    break // Stop processing this bucket
                                }

                                if (!isCandidateExplicitlyUnknown) {
                                    Logger.debug("Brute-force found valid argument: '$argCandidate' on field '$fieldName'")
                                    bucketValidArgs.add(argCandidate)
                                }
                            } catch (e: Exception) { /* Ignore */ }
                        }
                        bucketValidArgs
                    }
                }
            }
            deferredResults.forEach { deferred -> validArgs.addAll(deferred.await()) }
        }

        return@coroutineScope validArgs
    }
    /**
     * Probes the type of a specific argument by systematically trying different
     * JSON value types and analyzing the resulting error messages. This method
     * is more exhaustive and aligns with the original Clairvoyance strategy.
     */
    private suspend fun probeArgumentType(query: String, fieldName: String, argName: String): String {
        val probes = listOf(
            GraphQLString.name to "\"test\"",
            GraphQLInt.name to "123",
            GraphQLBoolean.name to "true",
            GraphQLFloat.name to "1.23",
            "InputObjectTrigger" to "{ ${RegexStore.WRONG_ARG_EXAMPLE}: null }",
            "Object" to "{}"
        )

        for ((assumedType, probeValue) in probes) {
            yield()

            var document = query.replace(RegexStore.WRONG_ARG_EXAMPLE, probeValue)
            try {
                val response = graphQLClient.send(document)
                val errors = response.optJSONArray("errors")

                if (errors != null && errors.length() > 0) {
                    for (i in 0 until errors.length()) {
                        val message = errors.getJSONObject(i).optString("message", "")

                        for (regex in RegexStore.WRONG_ARGUMENT_TYPES) {
                            val match = regex.find(message)
                            if (match != null) {
                                val discoveredType = match.groups["type"]?.value
                                if (discoveredType != null) {
                                    Logger.debug("Discovered arg type '$discoveredType' for '$argName' (opportunistic probe).")
                                    return discoveredType // Success! We're done.
                                }
                            }
                        }

                        val missingArgMatch = RegexStore.MISSING_ARGUMENT.find(message)
                        if (missingArgMatch != null && missingArgMatch.groups["argument"]?.value == argName) {
                            val discoveredType = missingArgMatch.groups["type"]?.value?.replace(Regex("[\\[\\]!]"), "")
                            if (discoveredType != null) {
                                Logger.debug("Discovered argument type '$discoveredType' for '$argName' from MISSING_ARGUMENT error.")
                                return discoveredType
                            }
                        }

                        if (assumedType == "InputObjectTrigger") {
                            val unknownFieldMatch = RegexStore.UNKNOWN_INPUT_FIELD.find(message)
                            unknownFieldMatch?.groups?.get("type")?.value?.let {
                                Logger.debug("Discovered InputObject type '$it' for '$argName' from UNKNOWN_INPUT_FIELD error.")
                                return it
                            }
                        }

                        if (assumedType == "Object") {
                            val inputObjectMatch = RegexStore.EXPECTED_INPUT_OBJECT.find(message)
                            inputObjectMatch?.groups?.get("type")?.value?.let {
                                Logger.debug("Discovered InputObject type '$it' for '$argName' from error.")
                                return it
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Logger.error("Exception during opportunistic probe for '$argName': ${e.message}")
            }

            document = query.replace(RegexStore.WRONG_ARG_EXAMPLE, probeValue).replace("}"," { __typename } }")

            try {
                val response = graphQLClient.send(document)
                val errors = response.optJSONArray("errors")
                if (errors != null) {
                    for (i in 0 until errors.length()) {
                        val message = errors.getJSONObject(i).optString("message", "")
                        for (regex in RegexStore.WRONG_ARGUMENT_TYPES) {
                            val match = regex.find(message)
                            if (match != null) {
                                val discoveredType = match.groups["type"]?.value
                                if (discoveredType != null) {
                                    Logger.debug("Discovered arg type '$discoveredType' for '$argName' (reliable probe).")
                                    return discoveredType // Success!
                                }
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Logger.error("Exception during reliable probe for '$argName': ${e.message}")
            }
        }

        Logger.debug("Could not determine type for argument '$argName' on field '$fieldName'. Defaulting to String.")
        return GraphQLString.name
    }
}