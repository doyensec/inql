package burp

import java.io.File
import java.io.PrintWriter

import org.python.util.PythonInterpreter
import org.python.core.PyObject

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

@Suppress("unused")
class BurpExtender: IBurpExtender, IExtensionStateListener, BurpExtension {

    companion object {
        // TODO: Find a way to sync version with git tags
        const val version = "5.0"
    }

    private var legacyApi: IBurpExtenderCallbacks? = null
    private var montoya: MontoyaApi? = null

    private var jython: PythonInterpreter? = null
    private var pythonPlugin: PyObject? = null

    // Legacy API gets instantiated first
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        // InQL requires Burp version 2023.1.2 or higher (this is the first stable release of Montoya API):
        // https://portswigger.net/burp/releases/professional-community-2023-1-2?requestededition=professional

        // Unfortunately, versions below 2022.3.3 will not load an extension at all, as they aren't compatible
        // with JVM 17. But at least for those running on JVM 17, we can show a more helpful error message if
        // they don't support Montoya API.

        // getBurpVersion() returns an array of strings, e.g. for 2022.3.3 CE: ['Burp Suite Community Edition', '2022', '3.3']
        val version_array = callbacks.getBurpVersion()

        // show helpful error message if version is below 2023.1.2 (version_array[1] is year, version_array[2] is major and minor style like '1.2')
        val year = version_array[1].toInt()

        // split version_array[2] and check if it has major and minor
        val versionParts = version_array[2].split(".")
        val major = versionParts[0].toInt()
        // if minor version is not present, consider it as '0'
        val minor = if (versionParts.size > 1) versionParts[1].toInt() else 0

        if ((year < 2023) or ((year == 2023) and (major == 1) and (minor < 2))) {
            val stdout = PrintWriter(callbacks.stdout, true)
            stdout.println("InQL v5 relies on the Montoya API, which is only supported in Burp versions 2023.1.2 or higher.")
            stdout.println("Unfortunately, your current Burp version (${version_array[1]}.${version_array[2]}) is outdated and incompatible.")
            stdout.println("")
            stdout.println("If InQL has stopped functioning unexpectedly, it's likely that an automatic update to v5 was installed via the BApp Store.")
            stdout.println("")
            stdout.println("To resolve this issue, please update your Burp installation or revert to InQL v4 by manually installing it from:")
            stdout.println("https://github.com/doyensec/inql/releases")

            callbacks.unloadExtension()
            throw Exception("InQL v5 is not compatible with your current Burp version.")
        }

        // Save legacy API for the functionality that still relies on it
        legacyApi = callbacks

        // Start embedded Python interpreter session (Jython)
        jython = PythonInterpreter()
    }

    // Montoya API gets instantiated second
    override fun initialize(montoyaApi: MontoyaApi) {
        // The new Montoya API should be used for all of the new functionality in InQL
        montoya = montoyaApi

        // Set the name of the extension
        montoya!!.extension().setName("InQL v$version")
        // The legacy API:
        //callbacks.setExtensionName("InQL v$version")

        // Instantiate the legacy Python plugin
        pythonPlugin = legacyPythonPlugin()

        // Pass execution to legacy Python code
        pythonPlugin!!.invoke("registerExtenderCallbacks")
    }

    private fun legacyPythonPlugin(): PyObject {
        // Make sure UTF-8 is used by default
        jython!!.exec("import sys; reload(sys); sys.setdefaultencoding('UTF8')")

        // Pass callbacks received from Burp to Python plugin as a global variable
        jython!!.set("callbacks", legacyApi)
        jython!!.set("montoya", montoya)

        // Instantiate legacy Python plugin
        jython!!.exec("from inql.extender import BurpExtenderPython")
        val legacyPlugin: PyObject = jython!!.eval("BurpExtenderPython(callbacks, montoya)")

        // Delete global after it has been consumed
        jython!!.exec("del callbacks, montoya")

        return legacyPlugin
    }

    override fun extensionUnloaded() {
        // Pass execution to legacy Python code
        pythonPlugin!!.invoke("extensionUnloaded")
    }
}
