package inql.scanner.scanresults

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import inql.Config
import inql.Logger
import inql.graphql.GQLSchema
import inql.history.HistoryTracker
import inql.scanner.ScanResult
import inql.scanner.SchemaDiscoverySource
import inql.scanner.ScannerTab
import inql.schema.corrections.SchemaCorrectionValidator
import inql.schema.corrections.SchemaCorrections
import inql.schema.corrections.SchemaCorrectionsService
import inql.ui.BorderPanel
import inql.ui.SendFromInqlHandler
import java.lang.ref.WeakReference
import inql.utils.QueryToRequestConverter
import javax.swing.JSplitPane
import javax.swing.tree.DefaultMutableTreeNode

class ScanResultsView(val scannerTab: ScannerTab) : BorderPanel(0) {
    private val treeView = ScanResultsTreeView(this)
    private val payloadView = ScanResultsContentView(this)
    private var currentNode: DefaultMutableTreeNode? = null
    private val sendToHandler = ScannerResultSendFromInqlHandler(this).also { it.setEnabled(false) }

    companion object {
        private val instances = mutableListOf<WeakReference<ScanResultsView>>()
        fun getAllInstances(): List<ScanResultsView> {
            instances.removeIf { it.get() == null }
            return instances.mapNotNull { it.get() }
        }
    }

    init {
        this.initUI()
        instances.add(WeakReference(this))
        this.payloadView.setContextMenuHandler(sendToHandler)
        this.sendToHandler.addKeyboardShortcutHandler(this)
        this.sendToHandler.addKeyboardShortcutHandler(treeView)
    }

    private fun initUI() {
        addHierarchyListener { e ->
            val changed = (e.changeFlags and java.awt.event.HierarchyEvent.DISPLAYABILITY_CHANGED.toLong()) != 0L
            if (changed && !isDisplayable) {
                dispose()
            }
        }

        val splitPane = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            this.treeView,
            this.payloadView,
        )

        splitPane.isOneTouchExpandable = true
        splitPane.rightComponent.isVisible = true
        splitPane.setDividerLocation(0.5)
        splitPane.resizeWeight = 0.2

        this.add(splitPane)
    }

    fun dispose() {
        instances.removeIf { it.get() === this || it.get() == null }
        for (l in hierarchyListeners) removeHierarchyListener(l)
    }

    fun release() {
        currentNode = null
        treeView.release()
        payloadView.release()
        dispose()
    }

    fun refresh() {
        this.treeView.refresh()
    }

    fun syncScanResult(updated: ScanResult): Boolean {
        return this.treeView.syncScanResult(updated)
    }

    fun repairTreeDisplay() {
        this.treeView.repairTreeDisplay()
    }

    fun openSchemaCorrections(scanResultUuid: String) {
        treeView.refreshKeepingSchemaCorrections(scanResultUuid)
    }

    fun ensureDefaultTreeExpansion() {
        this.treeView.ensureDefaultTreeExpansion()
    }

    private fun getNodeScanResult(node: DefaultMutableTreeNode): ScanResult? {
        var n = node
        while (n.userObject !is ScanResult && n.parent is DefaultMutableTreeNode) n = n.parent as DefaultMutableTreeNode
        val embedded = n.userObject as? ScanResult ?: return null
        return getScanResult(embedded.uuid) ?: embedded
    }

    /**
     * Rebuilds [requestTemplate] with a new body (same URL/service as the captured scan request).
     */
    internal fun requestTemplateWithBody(requestTemplate: HttpRequest, body: String): HttpRequest {
        return requestTemplate
            .withService(HttpService.httpService(requestTemplate.url()))
            .withBody(body)
    }

    fun selectionChangeListener(node: DefaultMutableTreeNode) {
        commitRequestTemplateEdits()
        when (val content = node.userObject) {
            is String -> {
                this.payloadView.load(content)
                this.sendToHandler.setEnabled(false)
            }
            is GQLQueryElement -> {
                // If it's a query/mutation/subscription, enable the handler
                this.payloadView.load(content)
                this.sendToHandler.setEnabled(true)
                this.currentNode = node
            }
            is GQLTypeElement -> {
                this.payloadView.load(content)
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            is CycleDetectionEntry -> {
                content.ensureLoaded { this.selectionChangeListener(node) }
                when (val payload = content.payload) {
                    CycleDetectionPayload.Loading -> this.payloadView.loadCycleLoading()
                    is CycleDetectionPayload.Ready -> this.payloadView.loadCycleResults(payload.scanResult, payload.cycles)
                }
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            is PathEnumerationEntry -> {
                this.payloadView.loadPathEnumeration(content)
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            is SchemaCorrectionsEntry -> {
                val scanResult = getNodeScanResult(node) ?: content.scanResult
                this.payloadView.loadSchemaCorrections(scanResult)
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            is RequestTemplateEntry -> {
                this.payloadView.loadRequestTemplate(scannerTab.requestTemplate)
                this.currentNode = null
                this.sendToHandler.setEnabled(false)
            }
            else -> Logger.error("Unknown node type selected! ${content.javaClass.name}")
        }
    }

    fun getPayloadText(): String = payloadView.getText()

    fun commitRequestTemplateEdits() {
        if (payloadView.selectedCard != ScanResultsContentView.REQUEST_TEMPLATE_CARD) return
        scannerTab.applyRequestTemplate(payloadView.currentRequestTemplate())
    }

    fun effectiveRequestTemplate(): HttpRequest {
        commitRequestTemplateEdits()
        return scannerTab.requestTemplate
    }

    fun getScanResult(uuid: String): ScanResult? {
        return scannerTab.scanResults.find { it.uuid == uuid }
    }

    fun applySchemaCorrections(scanResult: ScanResult, corrections: SchemaCorrections): Boolean {
        val (schema, errors) = SchemaCorrectionsService.validateAndApply(
            scanResult.parsedSchema.schema,
            corrections,
        )
        if (schema == null) {
            Logger.error("Schema correction failed: ${errors.joinToString("; ")}")
            return false
        }
        val updated = scanResult.withCorrectionsOnly(corrections)
        if (scanResult.schemaDiscoverySource == SchemaDiscoverySource.HISTORY) {
            HistoryTracker.storeCorrections(
                scanResult.host,
                corrections,
                scanResult.parsedSchema.schema,
            )
        }
        return updateScanResult(updated, keepSchemaCorrectionsOpen = true)
    }

    fun revertSchemaCorrections(scanResult: ScanResult): Boolean {
        val cleared = scanResult.withCorrectionsOnly(SchemaCorrections.EMPTY)
        if (!updateScanResult(cleared, keepSchemaCorrectionsOpen = true)) {
            return false
        }
        if (scanResult.schemaDiscoverySource == SchemaDiscoverySource.HISTORY && HistoryTracker.isRunning()) {
            HistoryTracker.storeCorrections(
                scanResult.host,
                SchemaCorrections.EMPTY,
                scanResult.parsedSchema.schema,
            )
        }
        return true
    }

    fun saveSdlSchema(scanResult: ScanResult, sdl: String): Boolean {
        val validation = SchemaCorrectionValidator.validateSdl(sdl)
        if (!validation.valid) {
            Logger.error("SDL validation failed: ${validation.errors.joinToString("; ")}")
            return false
        }
        val corrections = scanResult.schemaCorrections.withSdlOverride(sdl)
        if (scanResult.schemaDiscoverySource == SchemaDiscoverySource.HISTORY) {
            HistoryTracker.storeCorrections(
                scanResult.host,
                corrections,
                scanResult.parsedSchema.schema,
            )
        }
        return updateScanResult(scanResult.withCorrectionsOnly(corrections), keepSchemaCorrectionsOpen = true)
    }

    private fun updateScanResult(updated: ScanResult, keepSchemaCorrectionsOpen: Boolean = false): Boolean {
        val idx = scannerTab.scanResults.indexOfFirst { it.uuid == updated.uuid }
        if (idx < 0) return false
        scannerTab.scanResults[idx] = updated
        scannerTab.scanner.updateChildObjectAsync(updated)
        scannerTab.scanner.updateChildObjectAsync(scannerTab)
        if (scannerTab.url.isNotBlank()) {
            scannerTab.scanner.introspectionCache.putIfNewer(
                scannerTab.url,
                scanResult = updated.withUpdatedSchema(updated.effectiveParsedSchema()),
            )
        }
        if (!keepSchemaCorrectionsOpen) {
            refresh()
        } else {
            treeView.syncScanResult(updated)
        }
        return true
    }

    class ScannerResultSendFromInqlHandler(val view: ScanResultsView) :
        SendFromInqlHandler(view.scannerTab.inql, false) {

        override fun getRequest(): HttpRequest? {
            val node = view.currentNode ?: return null
            val scanResult = view.getNodeScanResult(node) ?: return null
            val converter = QueryToRequestConverter(scanResult)
            val query = converter.convert(
                node.toString(),
                node.parent.toString(),
                Config.getInstance().codegenDepth(),
            )
            return view.requestTemplateWithBody(view.effectiveRequestTemplate(), query)
        }

        override fun getText(): String {
            return view.getPayloadText()
        }
    }
}
