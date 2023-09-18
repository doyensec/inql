package burp

import burp.api.montoya.MontoyaApi

class Burp private constructor(callbacks: IBurpExtenderCallbacks, montoya: MontoyaApi) {
    companion object {
        private lateinit var instance: Burp

        val Callbacks: IBurpExtenderCallbacks get() = instance.callbacks
        val Helpers: IExtensionHelpers get() = instance.helpers
        val Montoya: MontoyaApi get() = instance.montoya

        fun initialize(callbacks: IBurpExtenderCallbacks, montoya: MontoyaApi) {
            if (this::instance.isInitialized) throw Exception("Burp Global already initialized!")
            instance = Burp(callbacks, montoya)
            System.setOut(montoya.logging().output())
            System.setErr(montoya.logging().error())
        }
    }

    private var callbacks: IBurpExtenderCallbacks
    private var helpers: IExtensionHelpers
    private var montoya: MontoyaApi

    init {
        this.callbacks = callbacks
        this.montoya = montoya
        helpers = callbacks.helpers
    }
}