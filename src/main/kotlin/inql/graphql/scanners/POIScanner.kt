package inql.graphql.scanners

import inql.Config
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import graphql.schema.*
import inql.graphql.GQLSchema
import inql.graphql.Utils
import inql.utils.JsonFileReader


class POIScanner(schema: GQLSchema) {
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
    }

    private var regexKeywords = mutableMapOf<String,String>()
    private var defaultKeywords = mutableListOf<String>()
    private val config = Config.getInstance()
    private val schema = schema

    init {
        val jsonString = JsonFileReader.readJsonFile("keywords.json")
        val gson = Gson()

        val type = object : TypeToken<List<KeywordCategory>>() {}.type
        val keywords = gson.fromJson<List<KeywordCategory>>(jsonString, type)
        val tmpKeywordsMap = mapOf(
            "report.poi.auth" to "auth",
            "report.poi.privileged" to "privileged",
            "report.poi.pii" to "pii",
            "report.poi.payment" to "payment",
            "report.poi.database" to "database",
            "report.poi.debugging" to "debugging",
            "report.poi.files" to "files"
        )

        // adding keywords enabled in settings
        for (k in tmpKeywordsMap) {
            if (config.getBoolean(k.key)!!) {
                defaultKeywords.add(k.value)
            }
        }

        for (keyword in keywords) {
            val kId = keyword.id

            if (kId !in defaultKeywords) {
                 continue
            }

            this.regexKeywords[kId] = keyword.keywords.joinToString("|")
        }

        val customKeywords = config.getString("report.poi.custom_keywords")!!

        if (customKeywords.isNotEmpty()) {
            this.regexKeywords["custom"] = customKeywords.lines().joinToString("|")
        }
    }

    fun scan(depth: Int = 4): Map<String, MutableList<FieldResult>> {
        val queries = schema.queries
        val mutations = schema.mutations
        val subscriptions = schema.subscriptions
        val results = mutableListOf<FieldResult>()
        val finalResults = mutableMapOf<String, MutableList<FieldResult>>()

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
            } else {
                finalResults[r.type]!!.add(r)
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
            if (Regex(regexPattern, RegexOption.IGNORE_CASE).containsMatchIn(field.name)) {
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