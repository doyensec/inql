package inql.scanner.scanresults

import inql.Config
import inql.session.Session
import inql.utils.JsonPrettifier
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel

/*
 * This class is a model for the JTree in the ScanResultsView. It is used to asynchronously
 * load the scan results and update the tree view with the results.
 *
 * Responsibilities:
 *   - Initially populate the tree with LazyLoadTreeNode objects (synchronously)
 *   - Manage a cache to store node content
 *   - Coordinate loading and preemptive loading tasks
 */
class ScanResultsTreeModel: DefaultTreeModel(DefaultMutableTreeNode("Scan Results")) {
    private val rootNode = root as DefaultMutableTreeNode

    suspend fun refresh(session: Session) {
        val config = Config.getInstance()
        rootNode.removeAllChildren()

        addQueries(session)
        addMutations(session)
        addPointsOfInterest(session, config)
        addCycleDetectionResults(session, config)
        addJsonSchema(session, config)
        addSdlSchema(session, config)

        reload(rootNode) // Notify model that changes have happened
    }

    private suspend fun addQueries(session: Session) {
        val queriesNode = ScanResultsTreeNode("Queries")
        session.gqlSchema?.listQueries()?.forEach {
            queriesNode.add(ScanResultsTreeNode(it) {
                ScanResult.GraphQL(session.gqlSchema?.getQuery(it)?.content ?: "")
            })
        }
        rootNode.add(queriesNode)
    }

    private suspend fun addMutations(session: Session) {
        val mutationsNode = ScanResultsTreeNode("Mutations")
        session.gqlSchema?.listMutations()?.forEach {
            mutationsNode.add(ScanResultsTreeNode(it) {
                ScanResult.GraphQL(session.gqlSchema?.getMutation(it)?.content ?: "")
            })
        }
        rootNode.add(mutationsNode)
    }

    private suspend fun addPointsOfInterest(session: Session, config: Config) {
        if (config.getBoolean("report.poi")) {
            val poiNode = ScanResultsTreeNode("Points of Interest")

            val poiFormat = config.getString("report.poi.format")
            if (poiFormat == "text" || poiFormat == "both") {
                session.gqlSchema?.getPointsOfInterest()?.forEach { (category, findings) ->
                    poiNode.add(ScanResultsTreeNode(category) {
                        ScanResult.Raw(
                            findings.joinToString("\n") { "- ${it.name}\n  ${it.content}" }) }) }
            }
            if (poiFormat == "json" || poiFormat == "both") {
                session.gqlSchema?.getPointsOfInterestAsJson()?.let {
                    poiNode.add(ScanResultsTreeNode("PointsOfInterest.json") {
                        ScanResult.Raw(JsonPrettifier.prettify(it)) }) }
            }
            rootNode.add(poiNode)
        }
    }

    private suspend fun addCycleDetectionResults(session: Session, config: Config) {
        if (config.getBoolean("report.cycles")) {
            val cycleDetectionResults = session.gqlSchema?.getCycleDetectionResultsAsText()
            if (!cycleDetectionResults.isNullOrBlank()) {
                rootNode.add(ScanResultsTreeNode("Cycle Detection") { ScanResult.Raw(cycleDetectionResults) })
            }
        }
    }

    private fun addJsonSchema(session: Session, config: Config) {
        if (config.getBoolean("report.json")) {
            rootNode.add(ScanResultsTreeNode("JSON schema") {
                ScanResult.Raw(JsonPrettifier.prettify(session.schema.json)) })
        }
    }

    private fun addSdlSchema(session: Session, config: Config) {
        if (config.getBoolean("report.sdl")) {
            rootNode.add(ScanResultsTreeNode("SDL schema") {
                ScanResult.Raw(session.schema.sdl) })
        }
    }
}