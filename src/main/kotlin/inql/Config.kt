package inql

import burp.Burp
import burp.api.montoya.core.HighlightColor
import inql.graphql.formatting.Formatter
import inql.graphql.formatting.SizedLRUCache
import kotlin.collections.set

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

    val defaults = mapOf<String, Any>(
        "codegen.depth" to 2,
        "codegen.pad" to 4,
        "integrations.browser.internal" to true,
        "integrations.browser.external.command" to "",
        "integrations.graphiql" to true,
        "integrations.voyager" to true,
        "integrations.webserver.lazy" to true,
        "report.json" to true,
        "report.sdl" to true,
        "report.cycles" to true,
        "report.cycles.depth" to 100,
        "report.poi" to true,
        "report.poi.depth" to 2,
        "report.poi.format" to "text",

        // hooks on POIScanner.kt
        "report.poi.auth" to true,
        "report.poi.privileged" to true,
        "report.poi.pii" to true,
        "report.poi.payment" to true,
        "report.poi.database" to true,
        "report.poi.debugging" to true,
        "report.poi.files" to true,

        "report.poi.deprecated" to true,
        "report.poi.custom_scalars" to true,
        "report.poi.show_custom_keywords" to true,
        "report.poi.custom_keywords" to "",
        "logging.level" to "WARNING",

        "bruteforcer.bucket_size" to 64,
        "bruteforcer.depth_limit" to 2,
        "bruteforcer.concurrency_limit" to 8,
        "bruteforcer.bruteforce_arguments" to true,
        "bruteforcer.custom_wordlist" to "",
        "bruteforcer.custom_arg_wordlist" to "",

        "proxy.highlight_enabled" to true,
        "proxy.highlight_color" to HighlightColor.BLUE.displayName(),
        "editor.formatting.enabled" to true,
        "editor.formatting.wordwrap" to true,
        "editor.formatting.timeout" to 1000, // Cutoff in milliseconds
        "editor.send_to.strip_comments" to true,
        "editor.formatting.cache_size_kb" to 102400, // 100 MB Default
    )

    val hooks = hashMapOf<String, (Any) -> Unit>(
        "logging.level" to { level ->
            Logger.setLevel(level.toString())
        },
        "editor.formatting.cache_size_kb" to { cacheSize ->
            val size = (cacheSize as? Number)?.toLong()
            if (size != null) {
                Formatter.globalCache.forEach { (_, value) ->
                    (value as? SizedLRUCache)?.maxBytes = size * 1024
                }
            } else {
                Logger.warning("Invalid type for 'editor.formatting.cache_size_kb': $cacheSize")
            }
        },
        "proxy.highlight_enabled" to { enabled ->
            if (enabled as Boolean) {
                ProxyRequestHighlighter.start()
            } else {
                ProxyRequestHighlighter.stop()
            }
        }
    )

    fun registerHook(key: String, hook: (Any) -> Unit) {
        hooks[key] = hook
    }

    fun triggerHook(key: String) {
        val value = get(key)
        if (value != null && hooks.containsKey(key)) {
            hooks[key]?.let { it(value) }
        }
    }

    fun getBoolean(key: String, scope: Scope = Scope.EFFECTIVE): Boolean? {
        var output: Boolean? = null
        var scopeLog: Scope? = null
        if (scope == Scope.PROJECT || scope == Scope.EFFECTIVE) {
            output = projectStore.getBoolean(key)
            scopeLog = Scope.PROJECT
        }
        if (output == null && (scope == Scope.GLOBAL || scope == Scope.EFFECTIVE || scope == Scope.EFFECTIVE_GLOBAL)) {
            output = globalStore.getBoolean(key)
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
//        Logger.debug(logStr)
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
            try {
                hooks[key]?.let { it(value) }
                Logger.debug("Hook executed for $key")
            } catch (e: Exception) {
                Logger.error("Failed to execute hook for $key: ${e.message}")
            }
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
            try {
                hooks[key]?.let { it(value) }
                Logger.debug("Hook executed for $key")
            } catch (e: Exception) {
                Logger.error("Failed to execute hook for $key: ${e.message}")
            }
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
            try {
                hooks[key]?.let { it(value) }
                Logger.debug("Hook executed for $key")
            } catch (e: Exception) {
                Logger.error("Failed to execute hook for $key: ${e.message}")
            }
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
            try {
                this.get(key, scope)?.let { newValue ->
                    hooks[key]?.let { it(newValue) }
                    Logger.debug("Hook executed for $key after deletion")
                }
            } catch (e: Exception) {
                Logger.error("Failed to execute hook for $key after deletion: ${e.message}")
            }
        }
    }

    fun reset(scope: Scope = Scope.PROJECT) {
        val keysToReset = this.keys(scope)
        keysToReset.forEach { key ->
            this.delete(key, scope)
        }

        keysToReset.filter { hooks.containsKey(it) }.forEach { key ->
            triggerHook(key)
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
        Logger.debug("PROJECT SETTINGS:")
        this.items(Scope.PROJECT).forEach {
            Logger.debug("${it.key} -> ${it.value}")
        }
        Logger.debug("GLOBAL SETTINGS:")
        this.items(Scope.GLOBAL).forEach {
            Logger.debug("${it.key} -> ${it.value}")
        }
        Logger.debug("DEFAULT SETTINGS:")
        this.items(Scope.DEFAULT).forEach {
            Logger.debug("${it.key} -> ${it.value}")
        }
    }
}
