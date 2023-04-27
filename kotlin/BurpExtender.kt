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
        // split version_array[2] before comparing
        val year = version_array[1].toInt()
        val major = version_array[2].split(".")[0].toInt()
        val minor = version_array[2].split(".")[1].toInt()
        if ((year < 2023) or ((year == 2023) and (major == 1) and (minor < 2))) {
            val stdout = PrintWriter(callbacks.stdout, true)

            stdout.println("InQL v5 depends on Montoya API which requires Burp version 2023.1.2 or higher.")
            stdout.println("Your Burp version is older and isn't supported: ${version_array[1]}.${version_array[2]}")
            stdout.println("")
            stdout.println("If InQL stopped working suddenly, it probably was installed from the BApp Store and")
            stdout.println("received an automatic update to v5.")
            stdout.println("")
            stdout.println("Update your Burp installation or revert to InQL v4 by installing it manually from:")
            stdout.println("https://github.com/doyensec/inql/releases")

            callbacks.unloadExtension()
            throw Exception("Burp version is too low for InQL v5.")
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
