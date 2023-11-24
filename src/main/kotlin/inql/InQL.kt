package inql

import burp.Burp
import burp.BurpExtender
import burp.BurpIcons
import burp.api.montoya.persistence.PersistedObject
import inql.attacker.Attacker
import inql.externaltools.ExternalToolsService
import inql.graphql.gqlspection.IGQLSpection
import inql.graphql.gqlspection.PyGQLSpection
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.scanner.Scanner
import inql.ui.*
import kotlinx.coroutines.runBlocking
import java.awt.Component
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

class InQL : TabbedPane(), SavesAndLoadData {

    private val config = Config.getInstance()
    private val profiles = LinkedHashMap<String, Profile>()
    val gqlspection: IGQLSpection

    // main tabs
    val scanner = Scanner(this)
    val attacker = Attacker(this)

    init {
        Burp.Montoya.logging().raiseInfoEvent("InQL ${BurpExtender.version} Started")

        // Cleanup from previous versions
        // FIXME: Remove this once this is exposed through Settings UI
        config.delete("logging.level", Config.Scope.PROJECT)
        config.delete("codegen.depth", Config.Scope.PROJECT)
        config.delete("codegen.pad", Config.Scope.PROJECT)
        config.delete("ScannerPanel", Config.Scope.GLOBAL)

        val logLevel = config.getString("logging.level") ?: "DEBUG"
        Logger.setLevel(logLevel)

        // Initialize PyGQLSpection
        val pyGQLSpection = PyGQLSpection.getInstance()
        this.gqlspection = pyGQLSpection
        runBlocking {
            pyGQLSpection.setLogLevel(logLevel)
        }

        // Register GraphQL Payload Editor
        Burp.Montoya.userInterface().registerHttpRequestEditorProvider(StyledPayloadEditor.getProvider(this))

        // Register Burp Scanner Checks
        Burp.Montoya.scanner().registerScanCheck(BurpScannerCheck())

        this.addTab("Scanner", this.scanner)
        this.addTab("Attacker", this.attacker)
        this.addSettingsTab()

        // Register the extension main tab
        Burp.Montoya.userInterface().registerSuiteTab("InQL", this)

        // Register context menu handler
        Burp.Montoya.userInterface().registerContextMenuItemsProvider(SendToInqlHandler(this))

        // Reload data from the project file
        if (!this.dataPresentInProjectFile()) {
            this.saveToProjectFile(false) // initialize main object
        } else {
            this.loadFromProjectFileAsync()
        }

        // Initialize ExternalToolsService to make it ready to spawn the webserver and register the interceptor when they are needed
        ExternalToolsService.init(this)

        // If enabled, start request highlighter
        if (this.config.getBoolean("proxy.highlight_enabled") == true) {
            ProxyRequestHighlighter.start()
        }
    }

    fun unload() = runBlocking {
        ProxyRequestHighlighter.stop()
        this@InQL.gqlspection.unload()
    }

    fun getAvailableProfileId(name: String): String {
        val sanitizedName = name
            .replace(Regex("\\s+"), "-")
            .replace(Regex("[^A-Za-z0-9-]+"), "_")
            .lowercase()
        var id = sanitizedName
        var i: UInt = 0u
        while (this.profiles.containsKey(id)) {
            i++
            id = "$sanitizedName-$i"
        }
        return id
    }

    fun getProfilesId(): Collection<String> {
        return this.profiles.keys
    }

    fun getProfiles(): Collection<Profile> {
        return this.profiles.values
    }

    fun getProfile(key: String): Profile? {
        return this.profiles[key]
    }

    fun deleteProfile(key: String) {
        if (this.profiles.containsKey(key)) {
            this.profiles[key]?.deleteFromProjectFileAsync()
            this.profiles.remove(key)
        }
    }

    fun deleteProfile(p: Profile) {
        this.deleteProfile(p.id)
    }

    fun createProfile(name: String, host: String): Profile {
        val id = getAvailableProfileId(name)
        val p = Profile(name, id, host)
        this.profiles[id] = p
        this.updateChildObjectAsync(p)
        return p
    }

    fun focus() {
        Logger.debug("Focusing InQL")
        (this.parent as JTabbedPane).selectedComponent = this
    }

    fun focusTab(tab: Component) {
        (this.parent as JTabbedPane).selectedComponent = this
        this.tabbedPane.selectedComponent = tab
    }

    private fun addSettingsTab() {
        val button = ImgButton("Settings", BurpIcons.CONFIG)
        button.background = this.background
        button.isFocusable = false
        button.addActionListener { SwingUtilities.invokeLater { SettingsWindow.getInstance().isVisible = true } }
        val idx = this.tabbedPane.tabCount
        this.addTab("Settings", JPanel())
        this.tabbedPane.setTabComponentAt(idx, button)
        this.tabbedPane.setEnabledAt(idx, false)
    }

    override val saveStateKey: String
        get() = "InQL_Main"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject> {
        val lst: MutableList<SavesDataToProject> = this.profiles.values.toMutableList()
        lst.add(this.scanner)
        lst.add(this.attacker)
        return lst
    }

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setStringList("profiles", getSaveStateKeys(this.profiles.values))
        return obj
    }

    override fun burpDeserialize(obj: PersistedObject) {
        val profilesLst = obj.getStringList("profiles")
        if (profilesLst != null) {
            for (profileId in profilesLst) {
                val p = Profile.Deserializer(profileId).get() ?: continue
                this.profiles[p.id] = p
            }
        }

        this.scanner.loadFromProjectFile()
        this.attacker.loadFromProjectFile()
    }
}
