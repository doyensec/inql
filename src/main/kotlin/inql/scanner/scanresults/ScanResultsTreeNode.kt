package inql.scanner.scanresults

import com.google.gson.Gson
import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.poi.POIScanner
import inql.scanner.ScanResult
import inql.utils.JsonPrettifier
import javax.swing.tree.DefaultMutableTreeNode

open class TreeNodeWithCustomLabel(val label: String, obj: Any?) : DefaultMutableTreeNode(obj) {
    override fun toString(): String {
        return this.label
    }
}

class GQLElementListTreeNode(label: String, val list: List<String>, val type: GQLSchema.OperationType, val schema: GQLSchema) :
    TreeNodeWithCustomLabel(label, null) {
    init {
        list.forEach {
            this.add(TreeNodeWithCustomLabel(it, GQLQueryElement(it, type, schema)))
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
        this.add(GQLElementListTreeNode("Queries", gqlSchema.queries.keys.sorted(), GQLSchema.OperationType.QUERY, gqlSchema))
        this.add(GQLElementListTreeNode("Mutations", gqlSchema.mutations.keys.sorted(), GQLSchema.OperationType.MUTATION, gqlSchema))
        this.add(GQLElementListTreeNode("Subscriptions", gqlSchema.subscriptions.keys.sorted(), GQLSchema.OperationType.SUBSCRIPTION, gqlSchema))



        // Add Points of Interest
        if (config.getBoolean("report.poi") == true) {
            val poiScanner = POIScanner(gqlSchema)
            val pois = poiScanner.scan(config.getInt("report.poi.depth")!!)

            val poiNode = TreeNodeWithCustomLabel("Points of Interest", pois)

            val poiFormat = config.getString("report.poi.format")
            if (poiFormat == "text" || poiFormat == "both") {
                for ((category, results) in pois) {
                    if (results.isEmpty()) continue

                    val categoryText = StringBuilder()
                    categoryText.appendLine("- $category")

                    for (poi in results) {
                        categoryText.appendLine("  ${poi.path}")
                    }
                    val categoryNode = TreeNodeWithCustomLabel(category, categoryText.toString())
                    poiNode.add(categoryNode)
                }
            }
            if (poiFormat == "json" || poiFormat == "both") {
                val jsonPoi = Gson().toJson(pois)
                if (!jsonPoi.isNullOrBlank()) {
                    poiNode.add(TreeNodeWithCustomLabel("points_of_interest.json", JsonPrettifier.prettify(jsonPoi)))
                }
            }
            this.add(poiNode)
        }

        /* TODO: implement cycle detection
        // Add cycle detection results
        if (config.getBoolean("report.cycles") == true) {
            val cycleDetectionResults = gqlSchema.getCycleDetectionResultsAsText()
            if (!cycleDetectionResults.isNullOrBlank()) {
                this.add(TreeNodeWithCustomLabel("Cycle Detection", cycleDetectionResults))
            }
        }
         */

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
