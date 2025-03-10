package inql.scanner.scanresults

import inql.Config
import inql.graphql.GQLSchema
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


        /* TODO: implement PoI
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
         */

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
