package inql.scanner.scanresults

import com.google.gson.Gson
import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.scanners.CyclesScanner
import inql.graphql.scanners.POIScanner
import inql.graphql.scanners.POIScanner.Companion.getActiveKeywordsCount
import inql.scanner.ScanResult
import inql.utils.JsonPrettifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import javax.swing.SwingWorker
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


class LazyTreeNodeWithCustomLabel(
    label: String,
    private val loader: suspend (LazyTreeNodeWithCustomLabel) -> List<DefaultMutableTreeNode>
) : TreeNodeWithCustomLabel(label, null, forceDirectory = true) {

    private var loaded = false

    init {
        add(DefaultMutableTreeNode("Loading..."))
    }

    fun ensureLoaded(model: DefaultTreeModel) {
        if (loaded) return
        loaded = true

        CoroutineScope(Dispatchers.Default).launch {
            try {
                val children = loader(this@LazyTreeNodeWithCustomLabel)
                withContext(Dispatchers.Swing) {
                    removeAllChildren()
                    children.forEach { add(it) }
                    model.nodeStructureChanged(this@LazyTreeNodeWithCustomLabel)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Swing) {
                    removeAllChildren()
                    add(DefaultMutableTreeNode("<error loading>"))
                    model.nodeStructureChanged(this@LazyTreeNodeWithCustomLabel)
                }
            }
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

        if (config.getBoolean("report.poi") == true && getActiveKeywordsCount() > 0) {
            val poiNode = LazyTreeNodeWithCustomLabel("Points of Interest") { parent ->
                val poiScanner = POIScanner(gqlSchema)
                val pois = poiScanner.scan(config.getInt("report.poi.depth")!!)

                val resultNodes = mutableListOf<DefaultMutableTreeNode>()
                val poiFormat = config.getString("report.poi.format")

                if (poiFormat == "text" || poiFormat == "both") {
                    for ((category, results) in pois) {
                        if (results.isEmpty()) continue
                        val categoryText = buildString {
                            for (poi in results) {
                                appendLine("(${poi.queryType})${poi.path}")
                            }
                        }
                        resultNodes.add(TreeNodeWithCustomLabel(category, categoryText))
                    }
                }
                if (poiFormat == "json" || poiFormat == "both") {
                    val jsonPoi = Gson().toJson(pois)
                    if (!jsonPoi.isNullOrBlank()) {
                        resultNodes.add(TreeNodeWithCustomLabel("points_of_interest.json", JsonPrettifier.prettify(jsonPoi), forceDirectory = false))
                    }
                }
                resultNodes
            }

            this.add(poiNode)
        }

        if (config.getBoolean("report.cycles") == true) {
            val cycleNode = LazyTreeNodeWithCustomLabel("Cycle Detection") { parent ->
                val cycleScanner = CyclesScanner(gqlSchema)
                cycleScanner.detect()
                val results = cycleScanner.cyclesAsString()

                if (results.isNotBlank()) {
                    listOf(TreeNodeWithCustomLabel("Cycles Summary", results))
                } else {
                    listOf(TreeNodeWithCustomLabel("No cycles detected","<no cycles detected>"))
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
