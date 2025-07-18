package inql.bruteforcer

import burp.api.montoya.http.message.requests.HttpRequest
import graphql.Scalars
import graphql.Scalars.GraphQLID
import graphql.Scalars.GraphQLString
import graphql.schema.*
import inql.Config
import inql.InQL
import inql.Logger
import inql.exceptions.EmptyOrIncorrectWordlistException
import inql.graphql.GQLSchema
import inql.graphql.GraphQLSchemaToSDL
import inql.utils.ResourceFileReader
import java.io.File
import java.util.*

class Bruteforcer(private val inql: InQL) {
    private var url: String = ""
    private var request: HttpRequest? = null
    private var bucketSize: Int = 64
    private var wordlist: List<String> = emptyList()

    companion object {
        private val NAME_REGEX = Regex("^[_A-Za-z][_0-9A-Za-z]*$")
    }

    enum class FuzzingContext(val value: String) {
        ARGUMENT("InputValue"),
        FIELD("Field")
    }

    enum class RootOperationType(val keyword: String) {
        QUERY("query"),
        MUTATION("mutation"),
        SUBSCRIPTION("subscription")
    }

    data class RootTypeNames(
        val queryType: String? = null,
        val mutationType: String? = null,
        val subscriptionType: String? = null
    )

    fun startFromRequest(req: HttpRequest): String {
        url = req.url()
        request = req
        bucketSize = Config.getInstance().getInt("bruteforcer.bucket_size") ?: 64

        var wordlistFile = Config.getInstance()
            .getString("bruteforcer.custom_wordlist")
            ?.takeIf { it.isNotEmpty() }
            ?: "wordlist.txt"

        loadWordlist(wordlistFile)

        return GraphQLSchemaToSDL.schemaToSDL(run())
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

    private fun run(): GraphQLSchema {
        var inputSchema: GraphQLSchema? = null
        var inputDocument = "query { FUZZ }"
        var ignored: MutableList<String> = mutableListOf(
            GraphQLString.name, GraphQLID.name, Scalars.GraphQLInt.name,
            Scalars.GraphQLFloat.name, Scalars.GraphQLBoolean.name
        )
        var iterations = 1

        while (true) {
            iterations++

            inputSchema = scan(inputDocument, inputSchema)

            val next = getTypeWithoutFields(inputSchema, ignored)
            ignored.add(next)

            if (next != "") {
                inputDocument = convertPathToQuery(inputSchema, getPathFromRoot(inputSchema, next))
            } else {
                break
            }

        }

        return inputSchema!!
    }

    private fun fetchRootTypeNames(): RootTypeNames {
        val result = mutableMapOf<RootOperationType, String?>()

        for (opType in RootOperationType.values()) {
            val document = "${opType.keyword} { __typename }"
            try {
                val json = Utils.sendGraphQLRequest(document, request!!)
                val typename = json.optJSONObject("data")?.optString("__typename")
                result[opType] = typename
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

    private fun buildSchemaFromRootNames(rootNames: RootTypeNames): GraphQLSchema {
        val types = listOfNotNull(
            rootNames.queryType,
            rootNames.mutationType,
            rootNames.subscriptionType
        ).associateWith { typeName ->
            GraphQLObjectType.newObject().name(typeName).build()
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

    private fun getPathFromRoot(schema: GraphQLSchema, targetTypeName: String): MutableList<String> {
        val pathFromRoot = LinkedList<String>()
        val visited = mutableSetOf<String>()

        val typeMap = schema.typeMap

        if (!typeMap.containsKey(targetTypeName)) {
            throw IllegalArgumentException("Type '$targetTypeName' not in schema!")
        }

        val roots = listOfNotNull(
            schema.queryType?.name,
            schema.mutationType?.name,
            schema.subscriptionType?.name
        )

        var currentName = targetTypeName

        while (!roots.contains(currentName)) {
            var found = false

            for ((_, type) in typeMap) {
                val objectType = type as? GraphQLFieldsContainer ?: continue

                for (field in objectType.fieldDefinitions) {
                    val unwrapped = GraphQLTypeUtil.unwrapAll(field.type)
                    val key = "${objectType.name}.${field.name}"

                    if (visited.contains(key)) continue

                    if ((unwrapped as? GraphQLNamedType)?.name == currentName) {
                        pathFromRoot.addFirst(field.name)
                        visited.add(key)
                        currentName = objectType.name
                        found = true
                        break
                    }
                }

                if (found) break
            }

            if (!found) {
                throw IllegalArgumentException(
                    "Could not find path from root to '$targetTypeName'.\nCurrent path: $pathFromRoot"
                )
            }
        }

        pathFromRoot.addFirst(currentName)
        return pathFromRoot
    }

    private fun convertPathToQuery(schema: GraphQLSchema, path: MutableList<String>): String {
        if (path.isEmpty()) {
            throw IllegalArgumentException("Path must not be empty")
        }

        var doc = "FUZZ"

        // Build nested structure from innermost to outermost
        while (path.size > 1) {
            val field = path.removeAt(path.lastIndex)
            doc = "$field { $doc }"
        }

        // Determine operation type (query, mutation, subscription)
        val operationType = when (val rootType = path.first()) {
            schema.queryType?.name -> "query"
            schema.mutationType?.name -> "mutation"
            schema.subscriptionType?.name -> "subscription"
            else -> throw IllegalArgumentException("Unknown operation type for root '$rootType'")
        }

        return "$operationType { $doc }"
    }

    private fun getTypeWithoutFields(schema: GraphQLSchema, ignored: List<String>): String {
        val ignoredSet = ignored ?: emptySet()

        // Iterate over all types in the schema
        for ((_, type) in schema.typeMap) {
            val unwrappedType = GraphQLTypeUtil.unwrapAll(type)
            if (unwrappedType is GraphQLObjectType) {
                if (unwrappedType.fieldDefinitions.isEmpty()
                    && unwrappedType.name !in ignoredSet
                ) {
                    return unwrappedType.name
                }
            } else if (unwrappedType !is GraphQLInputObjectType && unwrappedType is GraphQLNamedType) {
                // Fallback if type is not input and has no fields (non-object case)
                val fields = schema.getObjectType(unwrappedType.name)?.fieldDefinitions ?: emptyList()
                if (fields.isEmpty() && unwrappedType.name !in ignoredSet) {
                    return unwrappedType.name
                }
            }
        }

        return ""
    }

    fun probeTypename(inputDocument: String): String {
        val document = inputDocument.replace("FUZZ", RegexStore.WRONG_FIELD_EXAMPLE)

        val response = Utils.sendGraphQLRequest(document, request!!)
        val errors = response.optJSONArray("errors")

        if (errors == null) {
            Logger.debug(
                """Unable to get typename from $document.
               Field Suggestion might not be enabled on this endpoint. Using default "Query"."""
            )
            return "Query"
        }

        var match: MatchResult? = null

        for (regex in RegexStore.WRONG_TYPENAME) {
            for (i in 0 until errors.length()) {
                val errorMessage = errors.optJSONObject(i)?.optString("message") ?: continue
                match = regex.matchEntire(errorMessage)
                if (match != null) break
            }
            if (match != null) break
        }

        if (match == null) {
            Logger.debug(
                """Unknown error in `probeTypename`: "$errors" does not match any known regexes.
               Field Suggestion might not be enabled on this endpoint. Using default "Query"."""
            )
            return "Query"
        }

        return match.groups["typename"]?.value
            ?.replace("[", "")
            ?.replace("]", "")
            ?.replace("!", "")
            ?: "Query"
    }

    private fun probeValidFields(
        inputDocument: String
    ): Set<String> {
        val validFields = mutableSetOf<String>()

        for (i in wordlist.indices step bucketSize) {
            val bucket = wordlist.slice(i until minOf(i + bucketSize, wordlist.size))
            val document = inputDocument.replace("FUZZ", bucket.joinToString(" "))

            val response = Utils.sendGraphQLRequest(document, request!!)
            val errors = response.getJSONArray("errors")

            val currentValidFields = bucket.toMutableSet()

            for (j in 0 until errors.length()) {
                val errorMessage = errors.getJSONObject(j).optString("message") ?: return emptySet()

                if (
                    "must not have a selection since type" in errorMessage &&
                    "has no subfields" in errorMessage
                ) {
                    return emptySet()
                }

                // Remove invalid field
                val invalidFieldRegex = Regex("""Cannot query field ['"]([_A-Za-z][_0-9A-Za-z]*)['"]""")

                val match = invalidFieldRegex.find(errorMessage)
                match?.groups?.get(1)?.value?.let { currentValidFields.remove(it) }

                // Add any suggested valid fields
                currentValidFields += RegexStore.getValidFields(errorMessage)
            }

            validFields += currentValidFields
        }

        return validFields
    }


    private fun scan(inputDocument: String, inputSchema: GraphQLSchema?): GraphQLSchema {
        Logger.debug("input query = $inputDocument")

        var schema = inputSchema

        if (inputSchema == null) {
            var rootTypenames = fetchRootTypeNames()
            schema = buildSchemaFromRootNames(rootTypenames)
        }

        var typename = probeTypename(inputDocument)
        Logger.debug("__typename = {$typename}")

        var validFields = probeValidFields(inputDocument)

        validFields.forEach() {
            // TODO
        }


        return schema!!
    }


}