package inql.scanner.scanresults

import inql.Config
import inql.graphql.IGQLSchema
import inql.scanner.ScanResult
import inql.utils.JsonPrettifier
import java.time.format.DateTimeFormatter
import javax.swing.tree.DefaultMutableTreeNode

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
    TreeNodeWithCustomLabel(tsFormatter.format(scanResult.ts), scanResult) {
    companion object {
        private val tsFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    }

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
        val pois = gqlSchema.getPointsOfInterest()
        if (config.getBoolean("report.poi") == true && pois.isNotEmpty()) {
            val poiFormat = config.getString("report.poi.format")
            val poiNode = TreeNodeWithCustomLabel("Points of Interest", pois)
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
            val jsonPoi = gqlSchema.getPointsOfInterestAsJson()
            if ((poiFormat == "json" || poiFormat == "both") && !jsonPoi.isNullOrBlank()) {
                poiNode.add(TreeNodeWithCustomLabel("PointsOfInterest.json", JsonPrettifier.prettify(jsonPoi)))
            }
            this.add(poiNode)
        }

        // Add request template
        this.add(TreeNodeWithCustomLabel("Request Template", scanResult.requestTemplate.withBody("").toString()))

        // Add JSON schema
        if (config.getBoolean("report.introspection") == true && scanResult.rawSchema != null) {
            this.add(TreeNodeWithCustomLabel("JSON schema", JsonPrettifier.prettify(scanResult.rawSchema)))
        }
    }
}
