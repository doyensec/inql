package inql

import burp.Burp
import burp.api.montoya.core.BurpSuiteEdition
import java.io.File
import java.util.prefs.Preferences

class Config private constructor() {
    companion object {
        private lateinit var instance: Config
        fun getInstance(): Config {
            if (!this::instance.isInitialized) instance = Config()
            return instance
        }
    }

    enum class Scope {
        DEFAULT,
        GLOBAL,
        EFFECTIVE_GLOBAL,
        PROJECT,
        EFFECTIVE,
    }

    private val globalStore = Burp.Montoya.persistence().preferences()
    private val projectStore = Burp.Montoya.persistence().extensionData()

    private fun getInternalBrowserCommandMacOS(burpAppName: String): String? {
        // The command to run is something like
        //   open -a /Applications/Burp\ Suite\ Professional.app/Contents/Resources/app/burpbrowser/117.0.5938.62/Chromium.app https://google.com
        // But we need to figure out exact version of bundled Chromium
        val burpBrowserDir = "/Applications/${burpAppName}.app/Contents/Resources/app/burpbrowser"
        // Identify the first directory that contains subdirectory "Chromium.app"
        val chromiumDir = java.io.File(burpBrowserDir).listFiles()?.firstOrNull {
            it.isDirectory && it.listFiles()?.any {
                it.name == "Chromium.app"
            } == true
        }
        if (chromiumDir != null) {
            val chromiumVersion = chromiumDir.name
            return "open -a \"${burpBrowserDir}/${chromiumVersion}/Chromium.app\" \"%s\""
        }
        return null
    }

    private fun getInternalBrowserCommandWindows(burpAppName: String): String? {
        val userRegistryPath = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${burpAppName}"
        val systemRegistryPath = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${burpAppName}"

        val userInstallLocation = Preferences.userRoot().get(userRegistryPath + "\\InstallLocation", null)
        val systemInstallLocation = Preferences.systemRoot().get(systemRegistryPath + "\\InstallLocation", null)

        val installLocation = userInstallLocation ?: systemInstallLocation

        if (installLocation == null) {
            Logger.error("Could not find Burp Suite install location in registry.")
            return null
        }

        val burpBrowserDir = File(installLocation, "burpbrowser")

        val chromeDir = burpBrowserDir.listFiles { file ->
            file.isDirectory && File(file, "chrome.exe").exists()
        }?.firstOrNull()

        if (chromeDir == null) {
            Logger.error("Could not find Chromium in Burp Suite install location.")
            return null
        }

        // Check if we have a pre-wired browser profile (located in %APPDATA%\BurpSuite\pre-wired-browser)
        val browserProfileDir = File(System.getenv("APPDATA"), "BurpSuite\\pre-wired-browser")

        if (browserProfileDir.exists()) {
            val chromePath = File(chromeDir, "chrome.exe").absolutePath
            val userDataDir = browserProfileDir.absolutePath.replace("\\", "\\\\")

            return "\"$chromePath\" --user-data-dir=\"$userDataDir\" \"%s\""
        }

        Logger.error("Could not find pre-wired browser profile in %APPDATA%\\BurpSuite\\pre-wired-browser.")
        return null
    }

    fun getInternalBrowserCommand(): String? {
        val os = System.getProperty("os.name").lowercase()
        // if Burp.Montoya.burpSuite().version.edition() matches BurpSuiteEdition.PROFESSIONAL set to "Burp Suite Professional"
        // and if BurpSuiteEdition.COMMUNITY_EDITION then to "Burp Suite Community Edition"
        val edition = Burp.Montoya.burpSuite().version().edition()
        val name = if (edition == BurpSuiteEdition.PROFESSIONAL) {
            "Burp Suite Professional"
        } else if (edition == BurpSuiteEdition.COMMUNITY_EDITION) {
            "Burp Suite Community Edition"
        } else {
            Logger.error("Unknown Burp Suite edition: $edition")
            return null
        }

        if (os.contains("mac")) {
            return getInternalBrowserCommandMacOS(name)
        } else if (os.contains("win")) {
            return getInternalBrowserCommandWindows(name)
        } else {
            Logger.error("Unsupported OS: $os")
            return null
        }
    }

    private fun getDefaultBrowserCommand(): String {
        val os = System.getProperty("os.name").lowercase()
        return when {
            os.contains("win") -> "start %s"
            os.contains("mac") -> "open %s"
            else -> "xdg-open %s"
        }
    }

    val defaults = mapOf<String, Any>(
        "codegen.depth" to 2,
        "codegen.pad" to 4,
        "integrations.browser.internal" to if (getInternalBrowserCommand() != null) "embedded" else "external",
        "integrations.browser.external" to getDefaultBrowserCommand(),
        "integrations.graphiql" to true,
        "integrations.voyager" to true,
        "integrations.playground" to false,
        "integrations.altair" to false,
        "report.introspection" to true,
        "report.sdl" to false,
        "report.cycles" to false,
        "report.poi" to true,
        "report.poi.depth" to 2,
        "report.poi.format" to "text",
        "report.poi.auth" to true,
        "report.poi.privileged" to true,
        "report.poi.pii" to true,
        "report.poi.payment" to true,
        "report.poi.database" to true,
        "report.poi.debugging" to true,
        "report.poi.files" to true,
        "report.poi.deprecated" to true,
        "report.poi.custom_scalars" to true,
        "report.poi.custom_keywords" to "",
        "logging.level" to "WARN",
    )

    private val hooks = hashMapOf<String, (Any) -> Unit>(
        "logging.level" to { level -> Logger.setLevel(level.toString()) },
    )

    fun getBoolean(key: String, scope: Scope = Scope.EFFECTIVE): Boolean? {
        var output: Boolean? = null
        var scopeLog: Scope? = null
        if (scope == Scope.PROJECT || scope == Scope.EFFECTIVE) {
            output = projectStore.getBoolean(key)
            scopeLog = Scope.PROJECT
        }
        if (output == null && (scope == Scope.GLOBAL || scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            output = globalStore.getBoolean(key)
            scopeLog = Scope.GLOBAL
        }
        if (output == null && (scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            if (defaults[key] != null && defaults[key] is Boolean) {
                output = defaults[key] as Boolean
                scopeLog = Scope.DEFAULT
            }
        }

        var logStr = "Search Boolean $key (scope $scope): "
        logStr += if (output != null) {
            "found in $scopeLog with value $output"
        } else {
            "not found"
        }
        Logger.debug(logStr)
        return output
    }

    fun getInt(key: String, scope: Scope = Scope.EFFECTIVE): Int? {
        var output: Int? = null
        var scopeLog: Scope? = null
        if (scope == Scope.PROJECT || scope == Scope.EFFECTIVE) {
            output = projectStore.getInteger(key)
            scopeLog = Scope.PROJECT
        }
        if (output == null && (scope == Scope.GLOBAL || scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            output = globalStore.getInteger(key)
            scopeLog = Scope.GLOBAL
        }
        if (output == null && (scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            if (defaults[key] != null && defaults[key] is Int) {
                output = defaults[key] as Int
                scopeLog = Scope.DEFAULT
            }
        }

        var logStr = "Search Int $key (scope $scope): "
        logStr += if (output != null) {
            "found in $scopeLog with value $output"
        } else {
            "not found"
        }
        Logger.debug(logStr)
        return output
    }

    fun getString(key: String, scope: Scope = Scope.EFFECTIVE): String? {
        var output: String? = null
        var scopeLog: Scope? = null

        if (scope == Scope.PROJECT || scope == Scope.EFFECTIVE) {
            output = projectStore.getString(key)
            scopeLog = Scope.PROJECT
        }
        if (output == null && (scope == Scope.GLOBAL || scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            output = globalStore.getString(key)
            scopeLog = Scope.GLOBAL
        }
        if (output == null && (scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            if (defaults[key] != null && defaults[key] is String) {
                output = defaults[key] as String
                scopeLog = Scope.DEFAULT
            }
        }

        var logStr = "Search String $key (scope $scope): "
        logStr += if (output != null) {
            "found in $scopeLog with value $output"
        } else {
            "not found"
        }
        Logger.debug(logStr)
        return output
    }

    fun get(key: String, scope: Scope = Scope.EFFECTIVE): Any? {
        return getBoolean(key, scope) ?: getInt(key, scope) ?: getString(key, scope)
    }

    fun set(key: String, value: Boolean, scope: Scope = Scope.PROJECT) {
        Logger.debug("Setting config value: $key=$value (scope: $scope, type: Boolean)")
        when (scope) {
            Scope.PROJECT -> projectStore.setBoolean(key, value)
            Scope.GLOBAL -> globalStore.setBoolean(key, value)
            else -> throw Exception("Invalid scope provided to set(): $scope")
        }
        if (hooks.containsKey(key)) {
            hooks[key]?.let { it(value) }
        }
    }

    fun set(key: String, value: Int, scope: Scope = Scope.PROJECT) {
        Logger.debug("Setting config value: $key=$value (scope: $scope, type: Integer)")
        when (scope) {
            Scope.PROJECT -> projectStore.setInteger(key, value)
            Scope.GLOBAL -> globalStore.setInteger(key, value)
            else -> throw Exception("Invalid scope provided to set(): $scope")
        }
        if (hooks.containsKey(key)) {
            hooks[key]?.let { it(value) }
        }
    }

    fun set(key: String, value: String, scope: Scope = Scope.PROJECT) {
        Logger.debug("Setting config value: $key=$value (scope: $scope, type: String)")
        when (scope) {
            Scope.PROJECT -> projectStore.setString(key, value)
            Scope.GLOBAL -> globalStore.setString(key, value)
            else -> throw Exception("Invalid scope provided to set(): $scope")
        }
        if (hooks.containsKey(key)) {
            hooks[key]?.let { it(value) }
        }
    }

    fun delete(key: String, scope: Scope = Scope.PROJECT) {
        when (scope) {
            Scope.PROJECT -> {
                projectStore.deleteBoolean(key)
                projectStore.deleteInteger(key)
                projectStore.deleteString(key)
            }

            Scope.GLOBAL -> {
                globalStore.deleteBoolean(key)
                globalStore.deleteInteger(key)
                globalStore.deleteString(key)
            }

            else -> throw Exception("Invalid scope provided to delete(): $scope")
        }
        if (hooks.containsKey(key)) {
            hooks[key]?.let { this.get(key, scope)?.let { it1 -> it(it1) } }
        }
    }

    fun reset(scope: Scope = Scope.PROJECT) {
        this.keys(scope).forEach { key ->
            this.delete(key, scope)
        }
    }

    private fun keys(scope: Scope = Scope.PROJECT): List<String> {
        return when (scope) {
            Scope.DEFAULT -> defaults.keys.toList()
            Scope.GLOBAL -> listOf(
                globalStore.booleanKeys(),
                globalStore.integerKeys(),
                globalStore.stringKeys(),
            ).flatten()

            Scope.PROJECT -> listOf(
                projectStore.booleanKeys(),
                projectStore.integerKeys(),
                projectStore.stringKeys(),
            ).flatten()

            else -> ArrayList(0)
        }
    }

    private fun items(scope: Scope = Scope.PROJECT): Map<String, Any?> {
        return when (scope) {
            Scope.DEFAULT -> defaults
            else -> this.keys(scope).associateWith { key -> this.get(key, scope) }
        }
    }

    fun dumpContents() {
        Logger.info("PROJECT SETTINGS:")
        this.items(Scope.PROJECT).forEach {
            Logger.info("${it.key} -> ${it.value}")
        }
        Logger.info("GLOBAL SETTINGS:")
        this.items(Scope.GLOBAL).forEach {
            Logger.info("${it.key} -> ${it.value}")
        }
        Logger.info("DEFAULT SETTINGS:")
        this.items(Scope.DEFAULT).forEach {
            Logger.info("${it.key} -> ${it.value}")
        }
    }
}
