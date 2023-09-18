package burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import inql.InQL
import java.io.PrintWriter
import java.util.*

@Suppress("unused")
class BurpExtender : IBurpExtender, ExtensionUnloadingHandler, BurpExtension {

    val version =
        Properties().also { it.load(this.javaClass.getResourceAsStream("/version.properties")) }.getProperty("version")
            ?: ""
    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var inql: InQL

    private fun checkBurpVersion() {
        // InQL requires Burp version 2023.1.2 or higher (this is the first stable release of Montoya API):
        // https://portswigger.net/burp/releases/professional-community-2023-1-2?requestededition=professional

        // Unfortunately, versions below 2022.3.3 will not load an extension at all, as they aren't compatible
        // with JVM 17. But at least for those running on JVM 17, we can show a more helpful error message if
        // they don't support Montoya API.

        // getBurpVersion() returns an array of strings, e.g. for 2022.3.3 CE: ['Burp Suite Community Edition', '2022', '3.3']
        val versionArray = callbacks.burpVersion

        // show helpful error message if version is below 2023.1.2 (version_array[1] is year, version_array[2] is major and minor style like '1.2')
        val year = versionArray[1].toInt()

        // split version_array[2] and check if it has major and minor
        val versionParts = versionArray[2].split(".")
        val major = versionParts[0].toInt()
        // if minor version is not present, consider it as '0'
        val minor = if (versionParts.size > 1) versionParts[1].toInt() else 0

        if ((year < 2023) or ((year == 2023) and (major == 1) and (minor < 2))) {
            val stdout = PrintWriter(callbacks.stdout, true)
            stdout.println("InQL v5 relies on the Montoya API, which is only supported in Burp versions 2023.1.2 or higher.")
            stdout.println("Unfortunately, your current Burp version (${versionArray[1]}.${versionArray[2]}) is outdated and incompatible.")
            stdout.println("")
            stdout.println("If InQL has stopped functioning unexpectedly, it's likely that an automatic update to v5 was installed via the BApp Store.")
            stdout.println("")
            stdout.println("To resolve this issue, please update your Burp installation or revert to InQL v4 by manually installing it from:")
            stdout.println("https://github.com/doyensec/inql/releases")

            callbacks.unloadExtension()
            throw Exception("InQL v5 is not compatible with your current Burp version.")
        }
    }

    // Legacy API gets instantiated first
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        // Save legacy API for the functionality that still relies on it
        this.callbacks = callbacks
        checkBurpVersion()
    }

    // Montoya API gets instantiated second
    override fun initialize(montoyaApi: MontoyaApi) {
        // The new Montoya API should be used for all the new functionality in InQL
        Burp.initialize(montoyaApi)

        // Set the name of the extension
        montoyaApi.extension().setName(if (version.isNotEmpty()) "InQL $version" else "InQL")

        inql = InQL()
        montoyaApi.extension().registerUnloadingHandler(this)
    }

    override fun extensionUnloaded() {
        this.inql.unload()
    }
}
