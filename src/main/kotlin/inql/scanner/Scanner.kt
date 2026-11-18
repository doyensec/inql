package inql.scanner

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import inql.InQL
import inql.Logger
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.history.HistoryHostKey
import inql.history.HistoryTracker
import inql.graphql.Utils
import inql.schema.corrections.GraphQLErrorPathParser
import inql.schema.corrections.SchemaCorrections
import inql.schema.corrections.SchemaCorrectionsService
import inql.schema.corrections.TypeCorrectionTargetResolver
import java.lang.reflect.InvocationTargetException
import inql.ui.EditableTabTitle
import inql.ui.EditableTabbedPane
import java.net.URI
import java.net.URISyntaxException
import javax.swing.BorderFactory
import javax.swing.SwingUtilities
import javax.swing.event.ChangeEvent
import javax.swing.event.ChangeListener

class Scanner(val inql: InQL) : EditableTabbedPane(), SavesAndLoadData {
    private val tabFactory = ScannerTabFactory(this)
    val introspectionCache = IntrospectionCache(this.inql)

    companion object {
        private val SOURCE_TAB_TITLE_REGEX = Regex("""^\[([^\]]+)\]\s+(.+)$""")

        fun sourceTabTitle(source: SchemaDiscoverySource, host: String): String {
            return "[${source.treeLabelSuffix}] ${HistoryHostKey.normalize(host)}"
        }

        fun tabTitleForSourceParsing(tab: ScannerTab): String {
            var title = tab.getTabTitle().trim()
            tab.linkedProfile?.let { profile ->
                title = title.removeSuffix(" [${profile.name}]")
            }
            return title.trim()
        }

        fun parseSourceTabTitle(title: String): Pair<SchemaDiscoverySource, String>? {
            val match = SOURCE_TAB_TITLE_REGEX.matchEntire(title.trim()) ?: return null
            val label = match.groupValues[1]
            val host = HistoryHostKey.normalize(match.groupValues[2].trim())
            val source = SchemaDiscoverySource.entries.find { it.treeLabelSuffix == label } ?: return null
            return source to host
        }

        fun isSourceTab(tab: ScannerTab, source: SchemaDiscoverySource? = null): Boolean {
            parseSourceTabTitle(tabTitleForSourceParsing(tab))?.let { (tabSource, _) ->
                return source == null || tabSource == source
            }
            if (source == null) return false
            return tab.scanResults.isNotEmpty() &&
                tab.scanResults.all { it.schemaDiscoverySource == source }
        }

        fun isAnySourceTab(tab: ScannerTab): Boolean {
            if (parseSourceTabTitle(tabTitleForSourceParsing(tab)) != null) return true
            return tab.scanResults.isNotEmpty() &&
                tab.scanResults.map { it.schemaDiscoverySource }.distinct().size == 1
        }

        fun fetchHeadersForHost(
            host: String,
            pathFilter: String? = null,
            headersFilter: Map<String, String>? = null,
        ): Map<String, String>? {
            val reqList = Burp.Montoya.proxy().history {
                val reqUrl: URI
                try {
                    reqUrl = URI.create(it.finalRequest().url())
                } catch (_: URISyntaxException) {
                    return@history false
                }
                if (host.lowercase() != reqUrl.host) return@history false
                if (pathFilter != null && pathFilter.lowercase() != reqUrl.path.lowercase()) return@history false
                if (headersFilter != null) {
                    // "AND" matching for headers
                    for (reqHeader in it.finalRequest().headers()) {
                        if (headersFilter.containsKey(reqHeader.name()) && reqHeader.value()
                                .contains(headersFilter[reqHeader.name()] as String)
                        ) {
                            return@history false
                        }
                    }
                }
                return@history true
            }
            if (reqList.isEmpty()) {
                Logger.warning("No request found during headers fetching")
                return null
            }
            return reqList.last().finalRequest().headers().associate { it.name() to it.value() }
        }
    }

    init {
        this.border = BorderFactory.createEmptyBorder(5, 0, 0, 0)
        this.setTabComponentFactory(this.tabFactory)
        this.addTitleChangeListener { this.tabTitleChangeListener(it) }
        this.tabbedPane.addChangeListener {
            val selected = tabbedPane.selectedComponent as? ScannerTab ?: return@addChangeListener
            if (selected.scanResults.isEmpty()) return@addChangeListener
            SwingUtilities.invokeLater {
                selected.scanResultsView.repairTreeDisplay()
            }
        }
        this.newTab()
    }

    fun stop() {
        this.getScannerTabs().forEach {
            it.cancel()
        }
    }

    override fun closeTab(idx: Int) {
        val tab = this.tabbedPane.getComponentAt(idx) as ScannerTab
        super.closeTab(idx)
        tab.onClose()
    }

    private fun tabTitleChangeListener(e: EditableTabTitle) {
        val scannerTab = e.component as ScannerTab
        // Prevent empty titles
        var title = e.text
        if (title.trim() == "") {
            title = "${scannerTab.id}"
        }
        // Add profile name
        if (scannerTab.linkedProfile != null) {
            val suffix = " [${scannerTab.linkedProfile!!.name}]"
            if (!title.endsWith(suffix)) title = "${title}$suffix"
        }
        e.text = title

        // Update saved data if needed
        if (scannerTab.scanResults.isNotEmpty()) {
            scannerTab.saveToProjectFileAsync()
            // No need to update the Scanner's tab list as the ID doesn't change
        }
    }

    fun newTabFromRequest(req: HttpRequest) {
        val r_url = req.url()
        val tab = this.newTab(titleArg=r_url) as ScannerTab
        tab.url = r_url
        tab.requestTemplate = req.withBody("")
        this.inql.focusTab(this.inql.scanner)
    }

    fun findTabForHost(host: String): ScannerTab? {
        val normalizedHost = HistoryHostKey.normalize(host)
        return getScannerTabs().find { tab ->
            !isAnySourceTab(tab) && tabMatchesHost(tab, normalizedHost)
        }
    }

    fun findTabForHostAndSource(host: String, source: SchemaDiscoverySource): ScannerTab? {
        val normalizedHost = HistoryHostKey.normalize(host)
        return getScannerTabs().find { tab ->
            isSourceTab(tab, source) && tabMatchesHost(tab, normalizedHost, source)
        }
    }

    fun findHistoryTabForHost(host: String): ScannerTab? =
        findTabForHostAndSource(host, SchemaDiscoverySource.HISTORY)

    fun focusScannerTab(tab: ScannerTab) {
        val idx = tabbedPane.indexOfComponent(tab)
        if (idx >= 0) {
            tabbedPane.selectedIndex = idx
        }
    }

    fun getOrCreateSourceTab(
        host: String,
        source: SchemaDiscoverySource,
        requestTemplate: HttpRequest,
        focus: Boolean = false,
    ): ScannerTab {
        findTabForHostAndSource(host, source)?.let { return it }

        val normalizedHost = HistoryHostKey.normalize(host).ifBlank {
            HistoryHostKey.fromRequest(requestTemplate)?.let { HistoryHostKey.normalize(it) } ?: ""
        }
        findTabForHostAndSource(normalizedHost, source)?.let { return it }

        val scheme = try {
            java.net.URI.create(requestTemplate.url()).scheme ?: "https"
        } catch (_: Exception) {
            "https"
        }
        val url = "$scheme://$normalizedHost/"
        val title = sourceTabTitle(source, normalizedHost)
        val tab = this.newTab(titleArg = title, focus = focus) as ScannerTab
        tab.url = url
        tab.requestTemplate = requestTemplate
        tab.setTabTitle(title)
        return tab
    }

    fun applyScanResult(
        host: String,
        source: SchemaDiscoverySource,
        requestTemplate: HttpRequest,
        scanResult: ScanResult,
        focus: Boolean = false,
        incrementalTreeUpdate: Boolean = false,
    ) {
        val normalizedHost = HistoryHostKey.normalize(host)
        val tab = getOrCreateSourceTab(normalizedHost, source, requestTemplate, focus)
        val existing = tab.scanResults.find { it.schemaDiscoverySource == source }
        val resultToSave = if (existing != null) {
            val idx = tab.scanResults.indexOf(existing)
            val updated = if (source == SchemaDiscoverySource.HISTORY) {
                existing.withUpdatedSchema(scanResult.parsedSchema).let { base ->
                    if (scanResult.schemaCorrections != existing.schemaCorrections) {
                        base.withCorrections(scanResult.schemaCorrections, base.parsedSchema)
                    } else {
                        base
                    }
                }
            } else {
                scanResult
            }
            tab.scanResults[idx] = updated
            updated
        } else {
            tab.scanResults.add(scanResult)
            scanResult
        }
        tab.setTabTitle(sourceTabTitle(source, normalizedHost))
        val canSyncIncrementally = incrementalTreeUpdate && existing != null
        if (canSyncIncrementally && tab.scanResultsView.syncScanResult(resultToSave)) {
            tab.showResultsView()
            updateChildObjectAsync(resultToSave)
        } else {
            tab.showResultsView()
            if (focus) {
                inql.focusTab(inql.scanner)
                focusScannerTab(tab)
            }
            tab.scanResultsView.refresh()
            tab.scanResultsView.ensureDefaultTreeExpansion()
            updateChildObjectAsync(resultToSave)
            updateChildObjectAsync(tab)
        }
        introspectionCache.putIfNewer(url = tab.url, scanResult = resultToSave)
    }

    /**
     * Applies a type correction from a GraphQL "Did you mean" validation error to the schema for [host].
     * Prefer argument-scoped overrides from [request]'s query so unrelated fields keep their own input types.
     */
    fun applyTypeRenameCorrection(
        request: HttpRequest,
        host: String,
        wrongType: String,
        suggestedType: String,
    ): Boolean {
        val normalizedHost = HistoryHostKey.normalize(host)
        val tab = findHistoryTabForHost(normalizedHost)
            ?: findTabForHost(normalizedHost)
            ?: getScannerTabs().find { tabReferencesHost(it, normalizedHost) }
            ?: return false

        val scanResult = tab.scanResults.find { it.schemaDiscoverySource == SchemaDiscoverySource.HISTORY }
            ?: tab.scanResults.firstOrNull()
            ?: return false

        val corrections = buildScopedTypeCorrection(
            scanResult = scanResult,
            request = request,
            wrongType = wrongType,
            suggestedType = suggestedType,
        )
        val (schema, errors) = SchemaCorrectionsService.validateAndApply(
            scanResult.parsedSchema.schema,
            corrections,
        )
        if (schema == null) {
            Logger.error("Type rename correction failed: ${errors.joinToString("; ")}")
            return false
        }

        val updated = scanResult.withCorrectionsOnly(corrections)
        val idx = tab.scanResults.indexOfFirst { it.uuid == scanResult.uuid }
        if (idx < 0) return false
        tab.scanResults[idx] = updated

        if (updated.schemaDiscoverySource == SchemaDiscoverySource.HISTORY) {
            HistoryTracker.storeCorrections(
                updated.host,
                corrections,
                scanResult.parsedSchema.schema,
            )
        }

        updateChildObjectAsync(updated)
        updateChildObjectAsync(tab)
        if (tab.url.isNotBlank()) {
            introspectionCache.putIfNewer(
                tab.url,
                scanResult = updated.withUpdatedSchema(updated.effectiveParsedSchema()),
            )
        }

        SwingUtilities.invokeLater {
            tab.showResultsView()
            if (!tab.scanResultsView.syncScanResult(updated)) {
                tab.scanResultsView.refresh()
            }
            tab.scanResultsView.openSchemaCorrections(updated.uuid)
            inql.focusTab(inql.scanner)
            focusScannerTab(tab)
        }
        Logger.info("Applied type correction: $wrongType → $suggestedType for $normalizedHost")
        return true
    }

    private fun buildScopedTypeCorrection(
        scanResult: ScanResult,
        request: HttpRequest,
        wrongType: String,
        suggestedType: String,
    ): SchemaCorrections {
        val effectiveSchema = scanResult.effectiveParsedSchema().schema
        val operation = Utils.getGraphQLOperation(request)
        val querySites = operation?.let { op ->
            TypeCorrectionTargetResolver.argumentSitesInQuery(
                schema = effectiveSchema,
                query = op.query,
                wrongType = wrongType,
            )
        }.orEmpty()

        val targetSites = querySites.ifEmpty {
            TypeCorrectionTargetResolver.argumentSitesInSchema(effectiveSchema, wrongType)
        }

        val normalizedSuggested = GraphQLErrorPathParser.normalizeTypeName(suggestedType) ?: suggestedType
        val suggestedSdl = if (normalizedSuggested.endsWith("!")) normalizedSuggested else "$normalizedSuggested!"

        if (targetSites.isNotEmpty()) {
            var corrections = scanResult.schemaCorrections
            for (site in targetSites) {
                corrections = corrections.withArgumentTypeOverride(
                    parentType = site.parentType,
                    fieldName = site.fieldName,
                    argumentName = site.argumentName,
                    type = suggestedSdl,
                )
            }
            return corrections
        }

        return scanResult.schemaCorrections.withSuggestionRename(wrongType, suggestedType)
    }

    fun tabReferencesHost(tab: ScannerTab, normalizedHost: String): Boolean {
        return tabMatchesHost(tab, normalizedHost)
    }

    fun onTabClosed(tab: ScannerTab) {
        val url = tab.url
        val profileName = tab.linkedProfile?.name
        introspectionCache.evictForClosedTab(url, profileName)
        if (HistoryTracker.isRunning()) {
            for (host in tab.referencedHosts()) {
                HistoryTracker.releaseHostIfNoOpenTabs(host)
            }
        }
    }

    private fun tabMatchesHost(
        tab: ScannerTab,
        normalizedHost: String,
        source: SchemaDiscoverySource? = null,
    ): Boolean {
        val parsedTitle = parseSourceTabTitle(tabTitleForSourceParsing(tab))
        val titleSource = source ?: parsedTitle?.first
        if (titleSource != null) {
            parsedTitle?.let { (_, titleHost) ->
                if (HistoryHostKey.matches(titleHost, normalizedHost)) return true
            }
        }
        if (tab.url.isNotBlank()) {
            HistoryHostKey.fromUrl(tab.url)?.let { tabHostKey ->
                if (HistoryHostKey.matches(tabHostKey, normalizedHost)) return true
            }
        }
        try {
            val templateHostKey = HistoryHostKey.fromRequest(tab.requestTemplate)
            if (templateHostKey != null && HistoryHostKey.matches(templateHostKey, normalizedHost)) return true
        } catch (_: Exception) {
        }
        return tab.scanResults.any { result ->
            HistoryHostKey.matches(HistoryHostKey.normalize(result.host), normalizedHost)
        }
    }

    fun getScannerTabs(): List<ScannerTab> {
        return this.tabs.filterIsInstance<ScannerTab>().toList()
    }

    override val saveStateKey: String
        get() = "Scanner"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject> {
        return this.getScannerTabs().filter { it.scanResults.isNotEmpty() } // Only save tabs that have results
    }

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setInteger("tabFactoryIdx", this.tabFactory.tabIdx)
        val tabs = this.getChildrenObjectsToSave()
        obj.setStringList("tabs", getSaveStateKeys(tabs))
        Logger.debug("Saving ${tabs.size} tab(s) to project file")
        return obj
    }

    override fun burpDeserialize(obj: PersistedObject) {
        this.tabFactory.tabIdx = obj.getInteger("tabFactoryIdx")
        val tabIdList = obj.getStringList("tabs") ?: return

        Logger.debug("Loading ${tabIdList.size} tab(s) from project file")

        val tabsToFix = mutableSetOf<ScannerTab>()
        val restoredTabs = mutableListOf<ScannerTab>()
        for (tabId in tabIdList) {
            val id = tabId.substring(tabId.lastIndexOf('.') + 1).toInt()
            Logger.debug("Loading tab with id: $id")
            val tab = ScannerTab(this, id)
            tabsToFix.add(tab)
            if (!tab.loadFromProjectFile()) continue
            restoredTabs.add(tab)
        }

        restoreTabsOnEdt(restoredTabs, tabsToFix)
    }

    private fun restoreTabsOnEdt(restoredTabs: List<ScannerTab>, tabsToFix: MutableSet<ScannerTab>) {
        val restoreUi = Runnable {
            while (this.tabCount > 0) {
                this.tabbedPane.removeTabAt(0)
            }
            for (tab in restoredTabs) {
                this.addTab(tab.getTabTitle(), tab)
                tab.setTabTitle(tab.getTabTitle())
                tab.restoreResultsViewIfNeeded()
                tab.recoverHostKeyIfNeeded()?.let { host ->
                    Logger.info("Re-extracting history schema for $host after failed scan-result restore")
                    HistoryTracker.extractSchemaForHost(host)
                }
            }

            this.introspectionCache.populateFromScanner()

            // Blank tab for "new scan"; do not steal focus from restored tabs.
            this.newTab(focus = false)

            restoredTabs.firstOrNull()?.let { restored ->
                val idx = this.tabbedPane.indexOfComponent(restored)
                if (idx >= 0) {
                    this.tabbedPane.selectedIndex = idx
                }
            }

            class BuggyTreeUIFixer : ChangeListener {
                override fun stateChanged(e: ChangeEvent?) {
                    val selectedTab = tabbedPane.selectedComponent as? ScannerTab ?: return
                    if (!tabsToFix.contains(selectedTab)) {
                        return
                    }

                    SwingUtilities.invokeLater {
                        selectedTab.scanResultsView.repairTreeDisplay()
                    }

                    tabsToFix.remove(selectedTab)
                    if (tabsToFix.isEmpty()) {
                        tabbedPane.removeChangeListener(this)
                    }
                }
            }
            this.tabbedPane.addChangeListener(BuggyTreeUIFixer())
        }

        if (SwingUtilities.isEventDispatchThread()) {
            restoreUi.run()
        } else {
            try {
                SwingUtilities.invokeAndWait(restoreUi)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                Logger.error("Interrupted while restoring scanner tabs")
            } catch (e: InvocationTargetException) {
                Logger.error("Failed to restore scanner tabs: ${e.cause?.message ?: e.message}")
            }
        }
    }
}
