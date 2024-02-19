package inql.scanner

import burp.Burp
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import inql.Logger
import inql.Profile
import inql.graphql.GQLSchemaMemoryBackedImpl
import inql.graphql.Introspection
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.scanner.scanconfig.ScanConfigView
import inql.scanner.scanresults.ScanResultsView
import inql.ui.EditableTab
import inql.ui.ErrorDialog
import inql.utils.withUpsertedHeaders
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.awt.CardLayout
import java.io.File
import java.net.URI
import java.net.URISyntaxException
import javax.swing.JPanel

class ScannerTab(val scanner: Scanner, val id: Int) : JPanel(CardLayout()), SavesAndLoadData {
    companion object {
        const val SCAN_CONFIG_VIEW = "SCAN_CONFIG_VIEW"
        const val SCAN_RESULT_VIEW = "SCAN_RESULT_VIEW"
        val EXCLUDED_HEADERS = setOf<String>(
            // Keep these lowercase
            "connection",
            "host",
            "content-type",
            "content-length",
            "content-encoding",
            "accept",
            "accept-language",
            "accept-encoding",
            "cache-control",
            "origin"
        )
    }

    private var _tabTitle = "ScannerTab"
    val scanResults = ArrayList<ScanResult>(1)
    private var _linkedProfile: Profile? = null
    var linkedProfile: Profile?
        get() = this._linkedProfile
        set(new) {
            // Fix the tab tile with the new profile name before setting the new profile
            val prev = this._linkedProfile
            this._linkedProfile = new

            if (prev == null && new == null) return
            val currentTitle = this.getTabTitle()
            var newTitle = currentTitle
            if (prev != null) {
                // Remove old suffix
                val oldSuffix = " [${prev.name}]"
                newTitle = newTitle.removeSuffix(oldSuffix)
            }
            if (new != null) {
                // Add new suffix
                val newSuffix = " [${new.name}]"
                newTitle += newSuffix
            }
            this.setTabTitle(newTitle)
        }

    val inql = scanner.inql
    val scanConfigView = ScanConfigView(this)
    val scanResultsView = ScanResultsView(this)

    var url: String
        get() = this.scanConfigView.urlField.text
        set(s) {
            this.scanConfigView.urlField.text = s
        }
    var fileSchema: String?
        get() = this.scanConfigView.file
        set(s) {
            this.scanConfigView.file = s
        }

    val host: String?
        get() {
            return try {
                URI.create(this.url).host
            } catch (_: URISyntaxException) {
                null
            }
        }
    var requestTemplate: HttpRequest
        get() = this.scanConfigView.requestTemplate
        set(r) {
            this.scanConfigView.requestTemplate = r
        }

    private fun showView(card: String) {
        if (!setOf<String>(
                SCAN_CONFIG_VIEW,
                SCAN_RESULT_VIEW,
            ).contains(card)
        ) {
            throw Exception("Card ID not recognized: $card")
        }
        (this.layout as CardLayout).show(this, card)
    }

    fun showResultsView() {
        this.showView(SCAN_RESULT_VIEW)
    }

    fun showConfigView() {
        this.showView(SCAN_CONFIG_VIEW)
    }

    init {
        // initialize new page view and scanner view
        this.add(scanConfigView, SCAN_CONFIG_VIEW)
        this.add(scanResultsView, SCAN_RESULT_VIEW)
        this.showView(SCAN_CONFIG_VIEW)

        Burp.Montoya.userInterface().applyThemeToComponent(scanConfigView)
        Burp.Montoya.userInterface().applyThemeToComponent(scanResultsView)
    }

    fun loadFromProfile(p: Profile) {
        // Let's not load excluded headers
        val headers = p.customHeaders.filter { !EXCLUDED_HEADERS.contains(it.key.lowercase()) }
        // Let's not reset the current template to default, but add the headers to the existing one
        this.requestTemplate = this.requestTemplate.withUpsertedHeaders(headers)
    }

    fun saveToProfile(p: Profile) {
        val reqHeaders = this.requestTemplate.headers().associate { header -> header.name() to header.value() }
        val defaultHeaders = HttpRequest.httpRequest().withDefaultHeaders().headers()
            .associate { header -> header.name().lowercase() to header.value() }
        // Keep the header from the request if it's not a default one OR the value is different from the default
        val custom =
            reqHeaders
                .filter { (!defaultHeaders.containsKey(it.key.lowercase())) || (defaultHeaders.containsKey(it.key.lowercase()) && defaultHeaders[it.key] != it.value) }
                .filter { !EXCLUDED_HEADERS.contains(it.key.lowercase())  }
        p.overwrite(custom)
    }

    fun launchScan() {
        if (this.scanConfigView.verifyAndReturnUrl() == null) return
        this.normalizeHeaders()
        this.scanConfigView.setBusy(true)
        CoroutineScope(Dispatchers.IO).launch {
            this@ScannerTab.analyze()
        }
    }

    private fun normalizeHeaders() {
        val headers = this.requestTemplate.headers()
        if (headers.isEmpty()) return

        // ensure "Host" is the first header
        val hostIdx = headers.indexOfFirst { it.name().lowercase() == "host" }
        when (hostIdx) {
            -1 -> {
                // Not present, add it
                headers.add(0, HttpHeader.httpHeader("Host", this.host!!))
            }

            0 -> {
                // First header, OK
            }

            else -> {
                headers.removeAt(hostIdx)
                headers.add(0, HttpHeader.httpHeader("Host", this.host!!))
            }
        }

        // Ensure "Content-Type" is set
        val contentTypeIdx = headers.indexOfFirst { it.name().lowercase() == "content-type" }
        if (contentTypeIdx == -1) {
            headers.add(HttpHeader.httpHeader("Content-Type", "application/json"))
        } else if (!setOf("application/json", "application/graphql").contains(
                headers[contentTypeIdx].value().lowercase(),
            )
        ) {
            headers[contentTypeIdx] = HttpHeader.httpHeader("Content-Type", "application/json")
        }
    }

    private suspend fun analyze() {
        // Get the schema
        val jsonSchema: String?
        if (this.fileSchema != null && this.fileSchema!!.isNotBlank()) {
            Logger.info("GraphQL schema supplied as a file: ${this.fileSchema}")
            try {
                // FIXME: This is not ideal for big files,
                //  once GQLSpection is ported to Kotlin we can find a more suitable solution
                //  such as using a reader
                jsonSchema = File(this.fileSchema!!).readText()
            } catch (e: Exception) {
                scanFailed("Exception raised while reading file")
                return
            }
        } else {
            try {
                jsonSchema = Introspection.sendIntrospectionQuery(this.requestTemplate)
            } catch (e: Exception) {
                scanFailed("Could not parse introspection response from the endpoint")
                return
            }
            if (jsonSchema == null) {
                scanFailed("Introspection seems disabled for this endpoint")
                return
            }
        }

        // Invoke GQLSpection to analyze it
        val schema: GQLSchemaMemoryBackedImpl?
        try {
            schema = this.inql.gqlspection.parseSchema(jsonSchema)
        } catch (e: Exception) {
            scanFailed("Failed to deserialize JSON schema")
            return
        }
        if (schema == null) {
            scanFailed("GQLSpection failed to parse the schema")
            return
        }

        // Create a scan result
        val sr = ScanResult(this.host!!, this.requestTemplate, schema, jsonSchema)

        // This shouldn't cause an issue with concurrency since this list is only used in this specific ScannerTab
        // and multiple scans at the same time for the same ScannerTab are not allowed
        this.scanResults.add(sr)

        // Update this tab in burp's project file
        this.scanner.updateChildObjectAsync(this)
        this.scanCompleted()
    }

    private fun scanCompleted() {
        this.scanConfigView.setBusy(false) // Do we need this?
        this.showView(SCAN_RESULT_VIEW)
        this.scanResultsView.refresh()
        this.scanner.introspectionCache.putIfNewer(url = this.url, scanResult = this.scanResults.last())
    }

    private fun scanFailed(reason: String?) {
        if (!reason.isNullOrBlank()) ErrorDialog("Scan failed: $reason")
        this.scanConfigView.setBusy(false)
    }

    fun getTabTitle(): String {
        val idx = this.scanner.tabbedPane.indexOfComponent(this)
        if (idx == -1) return this._tabTitle
        val tab = this.scanner.tabbedPane.getTabComponentAt(idx) as EditableTab
        val title = tab.tabTitle
        return title.text
    }

    fun setTabTitle(text: String) {
        this._tabTitle = text
        val idx = this.scanner.tabbedPane.indexOfComponent(this)
        if (idx == -1) return
        val tab = this.scanner.tabbedPane.getTabComponentAt(idx) as EditableTab
        val title = tab.tabTitle
        title.text = text
    }

    fun onClose() {
        if (this.scanResults.isNotEmpty()) this.scanner.deleteChildObjectAsync(this)
    }

    override val saveStateKey: String
        get() = "Scanner.Tab.$id"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject> = this.scanResults

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setString("tabTitle", this.getTabTitle())
        obj.setString("url", this.url)
        obj.setHttpRequest("template", requestTemplate)
        if (this.fileSchema != null) {
            obj.setString("fileSchema", this.fileSchema)
        }
        val profile = this.linkedProfile
        if (profile != null) obj.setString("linkedProfileId", profile.id)
        obj.setStringList("results", getSaveStateKeys(this.scanResults))
        return obj
    }

    override fun burpDeserialize(obj: PersistedObject) {
        this.url = obj.getString("url")
        this.requestTemplate = obj.getHttpRequest("template")
        this.fileSchema = obj.getString("fileSchema")
        val profileId = obj.getString("linkedProfileId")
        this.linkedProfile = if (profileId != null) this.inql.getProfile(profileId) else null
        val resultsIdLst = obj.getStringList("results")
        if (!resultsIdLst.isNullOrEmpty()) {
            for (resultId in resultsIdLst) {
                this.scanResults.add(ScanResult.Deserializer(resultId).get() ?: continue)
            }
        }

        // Set the tab title AFTER setting the linked profile to prevent double suffix
        this.setTabTitle(obj.getString("tabTitle"))

        // Set the UI to show the results
        if (this.scanResults.isNotEmpty()) {
            this.showResultsView()
            this.scanResultsView.refresh()
        }
    }
}
