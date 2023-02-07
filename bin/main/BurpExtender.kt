package burp

import org.python.util.PythonInterpreter
import org.python.core.PyInstance
import org.python.core.PyObject

@Suppress("unused")
class BurpExtender: IBurpExtender, IExtensionStateListener {

    companion object {
        const val version = "5.0"
    }

    private var jython: PythonInterpreter? = null
    private var pythonPlugin: PyObject? = null

    init {
        // Start embedded Python interpreter session (Jython)
        jython = PythonInterpreter()
    }

    private fun legacyPythonPlugin(callbacks: IBurpExtenderCallbacks): PyObject {
        // Pass callbacks received from Burp to Python plugin as a global variable
        jython!!.set("callbacks", callbacks)

        // Instantiate legacy Python plugin
        jython!!.exec("from inql.burp_ext.extender import BurpExtenderPython")
        val legacyPlugin: PyObject = jython!!.eval("BurpExtenderPython(callbacks)")

        // Delete global after it has been consumed
        jython!!.exec("del callbacks")

        return legacyPlugin
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        // Instantiate the legacy Python plugin
        pythonPlugin = legacyPythonPlugin(callbacks)

        // Pass execution to legacy Python code
        pythonPlugin!!.invoke("registerExtenderCallbacks")
    }

    override fun extensionUnloaded() {
        // Pass execution to legacy Python code
        pythonPlugin!!.invoke("extensionUnloaded")
    }
}
