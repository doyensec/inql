package inql.scanner.scanresults

import inql.Config
import inql.graphql.IGQLSchema
import inql.scanner.ScanResult
import inql.utils.JsonPrettifier
import javax.swing.tree.DefaultMutableTreeNode
import inql.Logger

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import graphql.introspection.IntrospectionResultToSchema
import graphql.language.Document
import java.util.HashMap
import graphql.schema.idl.SchemaPrinter

open class TreeNodeWithCustomLabel(val label: String, obj: Any) : DefaultMutableTreeNode(obj) {
    override fun toString(): String {
        return this.label
    }
}

class GQLElementListTreeNode(label: String, val map: Map<String, IGQLSchema.IGQLElement>) :
    TreeNodeWithCustomLabel(label, map) {
    init {
        map.keys.toList().sorted().forEach {
            this.add(DefaultMutableTreeNode(map[it]))
        }
    }
}

class ScanResultTreeNode(val scanResult: ScanResult) :
    TreeNodeWithCustomLabel(scanResult.host, scanResult) {

    init {
        loadNodes()
    }

    fun loadNodes() {
        val gqlSchema = this.scanResult.parsedSchema
        val config = Config.getInstance()

        // Add queries and mutations
        this.add(GQLElementListTreeNode("Queries", gqlSchema.getQueries()))
        this.add(GQLElementListTreeNode("Mutations", gqlSchema.getMutations()))

        // Add Points of Interest
        if (config.getBoolean("report.poi") == true) {
            val pois = gqlSchema.getPointsOfInterest()
            val poiNode = TreeNodeWithCustomLabel("Points of Interest", pois)

            val poiFormat = config.getString("report.poi.format")
            if (poiFormat == "text" || poiFormat == "both") {
                for ((category, findings) in pois) {
                    if (findings.isEmpty()) continue
                    val categoryText = StringBuilder()
                    for (poi in findings) {
                        categoryText.appendLine("- ${poi.name()}")
                        categoryText.appendLine()
                        if (poi.content().isNotBlank()) {
                            categoryText.appendLine("  ${poi.content()}")
                            categoryText.appendLine()
                            categoryText.appendLine()
                        }
                    }
                    val categoryNode = TreeNodeWithCustomLabel(category, categoryText.toString())
                    poiNode.add(categoryNode)
                }
            }
            if (poiFormat == "json" || poiFormat == "both") {
                val jsonPoi = gqlSchema.getPointsOfInterestAsJson()
                if (!jsonPoi.isNullOrBlank()) {
                    poiNode.add(TreeNodeWithCustomLabel("PointsOfInterest.json", JsonPrettifier.prettify(jsonPoi)))
                }
            }
            this.add(poiNode)
        }

        // Add cycle detection results
        if (config.getBoolean("report.cycles") == true) {
            val cycleDetectionResults = gqlSchema.getCycleDetectionResultsAsText()
            if (!cycleDetectionResults.isNullOrBlank()) {
                this.add(TreeNodeWithCustomLabel("Cycle Detection", cycleDetectionResults))
            }
        }

        // Add request template
        this.add(TreeNodeWithCustomLabel("Request Template", scanResult.requestTemplate.withBody("").toString()))

        // Add JSON schema
        if (config.getBoolean("report.json") == true && scanResult.jsonSchema != null) {
            this.add(TreeNodeWithCustomLabel("JSON schema", JsonPrettifier.prettify(scanResult.jsonSchema)))
        }

        // Add SDL schema
        if (config.getBoolean("report.sdl") == true && scanResult.sdlSchema != null) {
            this.add(TreeNodeWithCustomLabel("SDL schema", scanResult.sdlSchema))
        }
    }
}
