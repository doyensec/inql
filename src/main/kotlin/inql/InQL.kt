package inql

import burp.Burp
import burp.BurpExtender
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
import javax.swing.*
import java.awt.*
import java.awt.event.*

class InQL : InQLTabbedPane(), SavesAndLoadData {

    private val config = Config.getInstance()
    val gqlspection: IGQLSpection

    // main tabs
    val scanner = Scanner(this)
    val attacker = Attacker(this)

    init {
        Burp.Montoya.logging().raiseInfoEvent("InQL ${BurpExtender.version} Started")
        config.dumpContents()

        // Cleanup from previous versions
        // FIXME: Remove this once this is exposed through Settings UI
        config.delete("logging.level", Config.Scope.PROJECT)
        config.delete("codegen.depth", Config.Scope.PROJECT)
        config.delete("codegen.pad", Config.Scope.PROJECT)
        config.delete("ScannerPanel", Config.Scope.GLOBAL)

        val logLevel = config.getString("logging.level")
        Logger.setLevel(logLevel)

        // Initialize PyGQLSpection
        gqlspection = PyGQLSpection.getInstance()
        runBlocking {
            gqlspection.setLogLevel(logLevel)
        }

        // Register GraphQL Payload Editor
        Burp.Montoya.userInterface().registerHttpRequestEditorProvider(StyledPayloadEditor.getProvider(this))

        // Register Burp Scanner Checks
        Burp.Montoya.scanner().registerScanCheck(BurpScannerCheck())

        this.addTab("InQL Scanner", this.scanner)
        this.addTab("InQL Attacker", this.attacker)

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
        if (!this.config.getBoolean("integrations.webserver.lazy")) {
            ExternalToolsService.startIfOff()
        }

        // If enabled, start request highlighter
        if (this.config.getBoolean("proxy.highlight_enabled")) {
            ProxyRequestHighlighter.start()
        }
    }

    fun unload() = runBlocking {
        ProxyRequestHighlighter.stop()
        gqlspection.unload()
    }

    fun focus() {
        Logger.debug("Focusing InQL")
        (this.parent as JTabbedPane).selectedComponent = this
    }

    fun focusTab(tab: Component) {
        (this.parent as JTabbedPane).selectedComponent = this
        this.tabbedPane.selectedComponent = tab
    }

    override val saveStateKey: String
        get() = "InQL_Main"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject> {
        val lst: MutableList<SavesDataToProject> = mutableListOf()
        // TODO: Add Sessions to the list, probably from SessionManager
        lst.add(this.attacker)
        return lst
    }

    override fun burpSerialize(): PersistedObject {
        // TODO: Go over all Sessions in SessionManager and save them

// old code, irrelevant now
//        val obj = PersistedObject.persistedObject()
//        obj.setStringList("profiles", getSaveStateKeys(this.profiles.values))
//        return obj
        return PersistedObject.persistedObject()
    }

    override fun burpDeserialize(obj: PersistedObject) {
        // TODO: Restore Sessions from the project file via SessionManager
        // Then create the tabs for each session

 // old code, irrelevant now
 //       val profilesLst = obj.getStringList("profiles")
 //       if (profilesLst != null) {
 //           for (profileId in profilesLst) {
 //               val p = Profile.Deserializer(profileId).get() ?: continue
 //               this.profiles[p.id] = p
 //           }
 //       }

 //       this.scanner.loadFromProjectFile()
 //       this.attacker.loadFromProjectFile()
    }
}
