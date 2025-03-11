package inql.graphql.poi

import inql.Config
import inql.graphql.GQLSchema
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import inql.graphql.Utils
import inql.utils.JsonFileReader


public class POIScanner(schema: GQLSchema) {
    companion object {
        data class KeywordCategory(
            val name: String,
            val id: String,
            val keywords: List<String>
        )

        data class FieldResult(
            val type: String,
            val path: String,
            val description: String?
        )
    }

    private var regexKeywords = mutableMapOf<String,String>()
    private var defaultKeywords = mutableListOf<String>()
    private var examinedTypes = mutableListOf<String>()
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
        var results = mutableListOf<FieldResult>()
        var finalResults = mutableMapOf<String, MutableList<FieldResult>>()

        for (q in queries) {
            results.addAll(scanField(q.value, "", depth))
        }

        for (r in results) {
            if (r.type !in finalResults) {
                finalResults[r.type] = mutableListOf(r)
            } else {
                finalResults[r.type]!!.add(r)
            }
        }

        return finalResults
    }

    private fun scanField(field: GraphQLFieldDefinition, path: String, depth: Int = 4): List<FieldResult> {
        var results = mutableListOf<FieldResult>()
        val newPath = "$path -> ${field.name}"

        if (config.getBoolean("report.poi.deprecated")!! && field.isDeprecated) {
            results.add(FieldResult(type = "deprecated", path = newPath, description = field.description))
        }

        if (config.getBoolean("report.poi.custom_scalars")!! &&
            field.type is GraphQLScalarType &&
            !Utils.isBuiltInScalarType(field.type as GraphQLScalarType)) {
            results.add(FieldResult(type = "custom scalar", path = newPath, description = field.description))
        }

        for (keywords in regexKeywords) {
            val regex = Regex(keywords.value, RegexOption.IGNORE_CASE)
            if (regex.containsMatchIn(field.name)) {
                results.add(FieldResult(type = keywords.key, path = newPath, description = field.description))
                break
            }
        }

        val newDepth = depth - 1

        if (newDepth < 0) {
            return results
        }

        if (
            field.type is GraphQLObjectType
        ) {
            for (fieldDef in (field.type as GraphQLObjectType).fieldDefinitions) {
                if (fieldDef.name in examinedTypes) {
                    continue
                }

                examinedTypes.add(fieldDef.name)
                results.addAll(scanField(fieldDef, newPath, newDepth))
            }
        }

        return results
    }


}