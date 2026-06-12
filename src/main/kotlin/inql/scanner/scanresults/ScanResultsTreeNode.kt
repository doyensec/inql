package inql.scanner.scanresults

import com.google.gson.Gson
import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.scanners.POIScanner
import inql.graphql.scanners.POIScanner.Companion.getActiveKeywordsCount
import inql.scanner.ScanResult
import inql.scanner.SchemaDiscoverySource
import inql.schema.corrections.SchemaTypeCatalog
import inql.utils.JsonPrettifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel

open class TreeNodeWithCustomLabel(var label: String, obj: Any?, val forceDirectory: Boolean = false) : DefaultMutableTreeNode(obj) {
    init {
        allowsChildren = forceDirectory
    }

    override fun toString(): String {
        return this.label
    }

    override fun getAllowsChildren(): Boolean {
        if (forceDirectory) return true
        return super.getAllowsChildren()
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

class LazyLeafTreeNode(
    label: String,
    private val loader: suspend () -> String
) : TreeNodeWithCustomLabel(label, null, forceDirectory = false) {

    private var loaded = false
    private var selectionRefreshCallback: (() -> Unit)? = null

    fun setSelectionRefreshCallback(callback: () -> Unit) {
        this.selectionRefreshCallback = callback
    }

    fun ensureLoaded(model: DefaultTreeModel) {
        if (loaded) return
        loaded = true

        CoroutineScope(Dispatchers.Default).launch {
            val content = try {
                loader()
            } catch (e: Exception) {
                "<error loading>"
            }

            withContext(Dispatchers.Swing) {
                this@LazyLeafTreeNode.userObject = content
                model.nodeChanged(this@LazyLeafTreeNode)
                selectionRefreshCallback?.invoke()
            }
        }
    }
}

class GQLElementListTreeNode(
    label: String,
    val list: List<String>,
    val type: GQLSchema.OperationType,
    private val schemaSupplier: () -> GQLSchema,
    private val maxDepth: Int? = null,
) : TreeNodeWithCustomLabel(label, null, forceDirectory = true) {
    init {
        list.forEach {
            this.add(TreeNodeWithCustomLabel(it, GQLQueryElement(it, type, schemaSupplier, maxDepth)))
        }
    }
}

class GQLTypeCategoryTreeNode(
    label: String,
    typeNames: List<String>,
    private val schemaSupplier: () -> GQLSchema,
) : TreeNodeWithCustomLabel(label, null, forceDirectory = true) {
    init {
        typeNames.forEach { typeName ->
            add(TreeNodeWithCustomLabel(typeName, GQLTypeElement(typeName, schemaSupplier)))
        }
    }
}

class GQLTypesTreeNode(private val schemaSupplier: () -> GQLSchema) :
    TreeNodeWithCustomLabel("Types", null, forceDirectory = true) {
    init {
        val catalog = SchemaTypeCatalog.fromSchema(schemaSupplier().schema)
        addCategory("Object types", catalog.outputTypes)
        addCategory("Input types", catalog.inputTypes)
        addCategory("Enum types", catalog.enumTypes.map { it.name })
        addCategory("Union types", catalog.unionTypes)
        addCategory("Scalar types", catalog.scalarTypes)
    }

    private fun addCategory(label: String, typeNames: List<String>) {
        if (typeNames.isEmpty()) return
        add(GQLTypeCategoryTreeNode(label, typeNames, schemaSupplier))
    }
}


class ScanResultTreeNode(scanResult: ScanResult) :
    TreeNodeWithCustomLabel(
        buildScanResultLabel(scanResult),
        scanResult,
        forceDirectory = true,
    ) {

    var scanResult: ScanResult = scanResult
        private set

    companion object {
        private val SCHEMA_BRANCH_LABELS = setOf(
            "Queries",
            "Mutations",
            "Subscriptions",
            "Types",
            "Points of Interest",
            "Cycle Detection",
            "JSON schema",
            "SDL schema",
        )

        private fun buildScanResultLabel(scanResult: ScanResult): String {
            return "${scanResult.host} (${scanResult.schemaDiscoverySource.treeLabelSuffix})"
        }
    }

    init {
        loadNodes()
    }

    private fun loadNodes() {
        removeAllChildren()
        val gqlSchema = scanResult.effectiveParsedSchema()
        for (node in buildSchemaBranchNodes(gqlSchema, scanResult)) {
            add(node)
        }
        addContentNode("Schema Corrections", SchemaCorrectionsEntry(scanResult))
        addContentNode("Request Template", RequestTemplateEntry())
    }

    fun reloadSchemaBranches(updated: ScanResult) {
        scanResult = updated
        userObject = updated
        label = buildScanResultLabel(updated)

        val removable = (0 until childCount).mapNotNull { index ->
            val child = getChildAt(index) as? TreeNodeWithCustomLabel ?: return@mapNotNull null
            if (child.label in SCHEMA_BRANCH_LABELS) child else null
        }
        removable.forEach { remove(it) }

        val gqlSchema = updated.effectiveParsedSchema()
        val freshBranches = buildSchemaBranchNodes(gqlSchema, updated)
        freshBranches.reversed().forEach { insert(it, 0) }

        for (index in 0 until childCount) {
            val child = getChildAt(index) as? DefaultMutableTreeNode ?: continue
            val childLabel = (child as? TreeNodeWithCustomLabel)?.label ?: continue
            when (childLabel) {
                "Schema Corrections" -> child.userObject = SchemaCorrectionsEntry(updated)
            }
        }
    }

    private fun buildSchemaBranchNodes(gqlSchema: GQLSchema, result: ScanResult): List<DefaultMutableTreeNode> {
        val config = Config.getInstance()
        val nodes = mutableListOf<DefaultMutableTreeNode>()

        val schemaSupplier = { result.effectiveParsedSchema() }
        val historyDisplayDepth = if (result.schemaDiscoverySource == SchemaDiscoverySource.HISTORY) {
            Config.getInstance().historyDisplayDepth()
        } else {
            null
        }
        nodes.add(
            GQLElementListTreeNode(
                "Queries",
                gqlSchema.queries.keys.sorted(),
                GQLSchema.OperationType.QUERY,
                schemaSupplier,
                historyDisplayDepth,
            ),
        )
        nodes.add(
            GQLElementListTreeNode(
                "Mutations",
                gqlSchema.mutations.keys.sorted(),
                GQLSchema.OperationType.MUTATION,
                schemaSupplier,
                historyDisplayDepth,
            ),
        )
        nodes.add(
            GQLElementListTreeNode(
                "Subscriptions",
                gqlSchema.subscriptions.keys.sorted(),
                GQLSchema.OperationType.SUBSCRIPTION,
                schemaSupplier,
                historyDisplayDepth,
            ),
        )
        nodes.add(GQLTypesTreeNode(schemaSupplier))

        POIScanner.registerHooks()
        if (config.getBoolean("report.poi") == true && getActiveKeywordsCount() > 0) {
            nodes.add(
                LazyTreeNodeWithCustomLabel("Points of Interest") {
                    val poiScanner = POIScanner(gqlSchema)
                    val pois = poiScanner.scan(config.getInt("report.poi.depth")!!)
                    val resultNodes = mutableListOf<DefaultMutableTreeNode>()
                    val poiFormat = config.getString("report.poi.format")

                    if (poiFormat == "text" || poiFormat == "both") {
                        for ((category, poiResults) in pois) {
                            if (poiResults.isEmpty()) continue
                            val categoryText = buildString {
                                for (poi in poiResults) {
                                    appendLine("(${poi.queryType})${poi.path}")
                                }
                            }
                            resultNodes.add(TreeNodeWithCustomLabel(category, categoryText))
                        }
                    }
                    if (poiFormat == "json" || poiFormat == "both") {
                        val jsonPoi = Gson().toJson(pois)
                        if (!jsonPoi.isNullOrBlank()) {
                            resultNodes.add(
                                TreeNodeWithCustomLabel("points_of_interest.json", JsonPrettifier.prettify(jsonPoi), forceDirectory = false),
                            )
                        }
                    }
                    resultNodes
                },
            )
        }

        if (config.getBoolean("report.cycles") == true) {
            nodes.add(TreeNodeWithCustomLabel("Cycle Detection", CycleDetectionEntry(result, gqlSchema), forceDirectory = false))
        }

        if (config.getBoolean("report.json") == true) {
            nodes.add(TreeNodeWithCustomLabel("JSON schema", JsonPrettifier.prettify(gqlSchema.jsonSchema), forceDirectory = false))
        }

        val sdl = gqlSchema.sdlSchema ?: result.sdlSchema
        if (config.getBoolean("report.sdl") == true && sdl != null) {
            nodes.add(TreeNodeWithCustomLabel("SDL schema", sdl, forceDirectory = false))
        }

        return nodes
    }

    private fun addContentNode(label: String, content: Any) {
        this.add(TreeNodeWithCustomLabel(label, content, forceDirectory = false))
    }
}
