package inql.graphql.scanners

import inql.Config
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import graphql.schema.*
import inql.Logger
import inql.graphql.GQLSchema
import inql.graphql.Utils
import inql.utils.ResourceFileReader

class POIScanner(private val schema: GQLSchema) {
    companion object {
        data class KeywordCategory(
            val name: String,
            val id: String,
            val keywords: List<String>
        )

        data class FieldResult(
            val type: String,
            val path: String,
            val queryType: String,
            val description: String?
        )

        private var regexKeywords = mutableMapOf<String,String>()
        private var defaultKeywords = mutableListOf<String>()

        fun getActiveKeywordsCount() = regexKeywords.size

        private val config = Config.getInstance()

        fun registerHooks() {
            val tmpKeywordsMap = mapOf(
                "report.poi.auth" to "auth",
                "report.poi.privileged" to "privileged",
                "report.poi.pii" to "pii",
                "report.poi.payment" to "payment",
                "report.poi.database" to "database",
                "report.poi.debugging" to "debugging",
                "report.poi.files" to "files",
                "report.poi.custom_keywords" to "custom_keywords"
            )

            tmpKeywordsMap.forEach { (configKey, _) ->
                if (!config.hooks.containsKey(configKey)) {
                    config.registerHook(configKey) {
                        rebuildKeywords(tmpKeywordsMap)
                    }
                }
            }

            // Initial sync with config
            rebuildKeywords(tmpKeywordsMap)
        }

        private fun rebuildKeywords(tmpKeywordsMap: Map<String, String>) {
            defaultKeywords.clear()
            regexKeywords.clear()

            tmpKeywordsMap.forEach { (configKey, keywordValue) ->
                if (config.getBoolean(configKey) == true) {
                    defaultKeywords.add(keywordValue)
                }
            }

            val jsonString = ResourceFileReader.readFile("keywords.json")
            val type = object : TypeToken<List<KeywordCategory>>() {}.type
            val keywords = Gson().fromJson<List<KeywordCategory>>(jsonString, type)

            for (keyword in keywords) {
                if (keyword.id in defaultKeywords) {
                    regexKeywords[keyword.id] = keyword.keywords.joinToString("|")
                }
            }

            if(config.getBoolean("report.poi.show_custom_keywords") == true) {
                val customKeywords = config.getString("report.poi.custom_keywords") ?: ""
                if (customKeywords.isNotEmpty()) {
                    regexKeywords["custom"] = customKeywords.lines().joinToString("|")
                }
            }

            Logger.debug("Active keywords: $defaultKeywords")
            Logger.debug("Regex map rebuilt: $regexKeywords")
        }
    }

    init {
        val type = object : TypeToken<List<KeywordCategory>>() {}.type
        val jsonString = ResourceFileReader.readFile("keywords.json")

        val keywords = Gson().fromJson<List<KeywordCategory>>(jsonString, type)
        for (keyword in keywords) {
            val kId = keyword.id

            if (kId !in defaultKeywords) {
                continue
            }

            regexKeywords[kId] = keyword.keywords.joinToString("|")
        }

//        val customKeywords = config.getString("report.poi.custom_keywords")!!
//        setCustomKeywords(customKeywords)

        Logger.debug("regexKeyword: '${regexKeywords}'")
        Logger.debug("defaultKeywords: '${defaultKeywords}'")
    }

    fun scan(depth: Int = 4): Map<String, MutableList<FieldResult>> {
        val queries = schema.queries
        val mutations = schema.mutations
        val subscriptions = schema.subscriptions
        val results = mutableListOf<FieldResult>()
        val finalResults = mutableMapOf<String, MutableList<FieldResult>>()
        val tmpResultsCache = mutableMapOf<String, MutableList<String>>() // for de-duplication

        for (q in queries) {
            results.addAll(scanField(q.value.type, "", "Query", depth))
        }

        for (q in mutations) {
            results.addAll(scanField(q.value.type, "", "Mutation", depth))
        }

        for (q in subscriptions) {
            results.addAll(scanField(q.value.type, "", "Subscription", depth))
        }

        for (r in results.distinct().toMutableList()) {
            if (r.type !in finalResults) {
                finalResults[r.type] = mutableListOf(r)
                tmpResultsCache[r.type] = mutableListOf(r.path)
            } else {
                if (r.path !in tmpResultsCache[r.type]!!) {
                    finalResults[r.type]!!.add(r)
                    tmpResultsCache[r.type]!!.add(r.path)
                }
            }
        }

        return finalResults
    }

    private fun scanField(
        type: GraphQLType,
        currentPath: String,
        queryType: String,
        depth: Int = 4
    ): List<FieldResult> {
        val results = mutableListOf<FieldResult>()
        val unwrappedType = GraphQLTypeUtil.unwrapAll(type)

        // Base case: stop recursion at depth 0
        if (depth < 0) return results

        // Handle different GraphQL types
        when (unwrappedType) {
            is GraphQLObjectType -> {
                // Process object type fields
                unwrappedType.fieldDefinitions.forEach { field ->
                    val fieldPath = "$currentPath -> ${field.name}"

                    // Check field-level concerns
                    results.addAll(checkField(field, fieldPath, queryType))

                    // Recurse into field type
                    results.addAll(scanField(
                        type = field.type,
                        currentPath = fieldPath,
                        queryType = queryType,
                        depth = depth - 1
                    ))
                }
            }

            is GraphQLList -> {
                // Recurse into list item type
                results.addAll(scanField(
                    type = unwrappedType.wrappedType,
                    currentPath = currentPath,
                    queryType = queryType,
                    depth = depth
                ))
            }

            is GraphQLScalarType -> {
                // Handle scalar type reporting
                if (config.getBoolean("report.poi.custom_scalars")!! &&
                    !Utils.isBuiltInScalarType(unwrappedType)) {
                    results.add(FieldResult(
                        type = "custom scalar",
                        path = currentPath,
                        queryType = queryType,
                        description = unwrappedType.description
                    ))
                }
            }

            is GraphQLTypeReference -> {
                // Resolve type references
                schema.schema.getType((unwrappedType as GraphQLTypeReference).name)?.let { resolvedType ->
                    results.addAll(scanField(
                        type = resolvedType,
                        currentPath = currentPath,
                        queryType = queryType,
                        depth = depth
                    ))
                }
            }

        }

        return results
    }

    private fun checkField(
        field: GraphQLFieldDefinition,
        path: String,
        queryType: String
    ): List<FieldResult> {
        val results = mutableListOf<FieldResult>()

        // Check for deprecated fields
        if (config.getBoolean("report.poi.deprecated")!! && field.isDeprecated) {
            results.add(FieldResult(
                type = "deprecated",
                path = path,
                queryType = queryType,
                description = field.description
            ))
        }

        // Check field name against regex keywords
        for ((keywordName, regexPattern) in regexKeywords) {
            if (Regex("(\\\\W|^|_)($regexPattern)(\\\\W|\$|_)", RegexOption.IGNORE_CASE).containsMatchIn(field.name)) {
                results.add(FieldResult(
                    type = keywordName,
                    path = path,
                    queryType = queryType,
                    description = field.description
                ))
                break
            }
        }

        return results
    }

}