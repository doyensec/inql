package burp

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

    init {
        // Start embedded Python interpreter session (Jython)
        jython = PythonInterpreter()
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

    // Legacy API gets instantiated first
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        // Save legacy API for the functionality that still relies on it
        legacyApi = callbacks
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

    override fun extensionUnloaded() {
        // Pass execution to legacy Python code
        pythonPlugin!!.invoke("extensionUnloaded")
    }
}
