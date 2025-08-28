package inql.scanner.scanresults

import com.google.gson.Gson
import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.scanners.CyclesScanner
import inql.graphql.scanners.POIScanner
import inql.graphql.scanners.POIScanner.Companion.getActiveKeywordsCount
import inql.scanner.ScanResult
import inql.utils.JsonPrettifier
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel

open class TreeNodeWithCustomLabel(val label: String, obj: Any?, val forceDirectory: Boolean = false) : DefaultMutableTreeNode(obj) {
    override fun toString(): String {
        return this.label
    }

    override fun isLeaf(): Boolean {
        if (forceDirectory) return false
        return super.isLeaf()
    }
}

//class LazyTreeNodeWithCustomLabel(
//    label: String,
//    private val loader: () -> String
//) : TreeNodeWithCustomLabel(label, null, forceDirectory = true) {
//
//    private var loaded = false
//
//    init {
//        add(DefaultMutableTreeNode("Loading..."))
//    }
//
//    fun ensureLoaded(model: DefaultTreeModel) {
//        if (!loaded) {
//            removeAllChildren()
//            val result = loader()
//            if (result.isNotBlank()) {
//                add(DefaultMutableTreeNode(result))
//            } else {
//                add(DefaultMutableTreeNode("<no cycles detected>"))
//            }
//            loaded = true
//            model.nodeStructureChanged(this)
//        }
//    }
//}
class LazyTreeNodeWithCustomLabel(
    label: String,
    private val loader: (LazyTreeNodeWithCustomLabel) -> Unit
) : TreeNodeWithCustomLabel(label, null, forceDirectory = true) {

    private var loaded = false

    init {
        // Add dummy child so expand arrow shows
        add(DefaultMutableTreeNode("Loading..."))
    }

    fun ensureLoaded(model: DefaultTreeModel) {
        if (!loaded) {
            removeAllChildren()
            loader(this)   // let the lambda populate this node
            loaded = true
            model.nodeStructureChanged(this)
        }
    }
}

class GQLElementListTreeNode(label: String, val list: List<String>, val type: GQLSchema.OperationType, val schema: GQLSchema) :
    TreeNodeWithCustomLabel(label, null, forceDirectory = true) {
    init {
        list.forEach {
            this.add(TreeNodeWithCustomLabel(it, GQLQueryElement(it, type, schema)))
        }
    }
}


class ScanResultTreeNode(val scanResult: ScanResult) :
    TreeNodeWithCustomLabel(scanResult.host, scanResult) {
    private var poiNode: TreeNodeWithCustomLabel? = null

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
        POIScanner.registerHooks()

//        if (config.getBoolean("report.poi") == true && getActiveKeywordsCount() > 0) {
//            val poiScanner = POIScanner(gqlSchema)
//            val pois = poiScanner.scan(config.getInt("report.poi.depth")!!)
//
//            poiNode = TreeNodeWithCustomLabel("Points of Interest", pois)
//            val poiFormat = config.getString("report.poi.format")
//            if (poiFormat == "text" || poiFormat == "both") {
//                for ((category, results) in pois) {
//                    if (results.isEmpty()) continue
//
//                    val categoryText = StringBuilder()
//                    categoryText.appendLine("- $category")
//
//                    for (poi in results) {
//                        categoryText.appendLine("(${poi.queryType})${poi.path}")
//                    }
//                    val categoryNode = TreeNodeWithCustomLabel(category, categoryText.toString())
//                    poiNode?.add(categoryNode)
//                }
//            }
//            if (poiFormat == "json" || poiFormat == "both") {
//                val jsonPoi = Gson().toJson(pois)
//                if (!jsonPoi.isNullOrBlank()) {
//                    poiNode?.add(TreeNodeWithCustomLabel("points_of_interest.json", JsonPrettifier.prettify(jsonPoi)))
//                }
//            }
//            this.add(poiNode)
//        }

        if (config.getBoolean("report.poi") == true && getActiveKeywordsCount() > 0) {
            val poiNode = LazyTreeNodeWithCustomLabel("Points of Interest") { parent ->
                val poiScanner = POIScanner(gqlSchema)
                val pois = poiScanner.scan(config.getInt("report.poi.depth")!!)

                val poiFormat = config.getString("report.poi.format")
                if (poiFormat == "text" || poiFormat == "both") {
                    for ((category, results) in pois) {
                        if (results.isEmpty()) continue

                        val categoryText = buildString {
                            appendLine("- $category")
                            for (poi in results) {
                                appendLine("(${poi.queryType})${poi.path}")
                            }
                        }
                        parent.add(TreeNodeWithCustomLabel(category, categoryText))
                    }
                }
                if (poiFormat == "json" || poiFormat == "both") {
                    val jsonPoi = Gson().toJson(pois)
                    if (!jsonPoi.isNullOrBlank()) {
                        parent.add(TreeNodeWithCustomLabel("points_of_interest.json", JsonPrettifier.prettify(jsonPoi)))
                    }
                }
            }

            this.add(poiNode)
        }

        if (config.getBoolean("report.cycles") == true) {
            val cycleNode = LazyTreeNodeWithCustomLabel("Cycle Detection") { parent ->
                val cycleScanner = CyclesScanner(gqlSchema)
                cycleScanner.detect()
                val results = cycleScanner.cyclesAsString()
                if (results.isNotBlank()) {
                    parent.add(DefaultMutableTreeNode(results))
                } else {
                    parent.add(DefaultMutableTreeNode("<no cycles detected>"))
                }
            }
            this.add(cycleNode)
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
