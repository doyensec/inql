package burp

import burp.api.montoya.MontoyaApi

class Burp private constructor() {
    companion object {
        private lateinit var montoya: MontoyaApi
        val Montoya: MontoyaApi get() = montoya
        fun initialize(montoya: MontoyaApi) {
            if (this::montoya.isInitialized) throw Exception("Burp Global already initialized!")
            Burp.montoya = montoya
            System.setOut(montoya.logging().output())
            System.setErr(montoya.logging().error())
        }
    }
}
