package inql

import burp.Burp
import burp.api.montoya.core.HighlightColor

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

    interface Store {
        fun getBoolean(key: String): Boolean?
        fun getInteger(key: String): Int?
        fun getString(key: String): String?

        fun setBoolean(key: String, value: Boolean)
        fun setInteger(key: String, value: Int)
        fun setString(key: String, value: String)

        fun deleteBoolean(key: String)
        fun deleteInteger(key: String)
        fun deleteString(key: String)

        fun booleanKeys(): Set<String>
        fun integerKeys(): Set<String>
        fun stringKeys(): Set<String>
    }

    class PreferencesStore(private val preferences: burp.api.montoya.persistence.Preferences) : Store {
        override fun getBoolean(key: String): Boolean? = preferences.getBoolean(key)
        override fun setBoolean(key: String, value: Boolean) = preferences.setBoolean(key, value)
        override fun getInteger(key: String): Int? = preferences.getInteger(key)
        override fun setInteger(key: String, value: Int) = preferences.setInteger(key, value)
        override fun getString(key: String): String? = preferences.getString(key)
        override fun setString(key: String, value: String) = preferences.setString(key, value)
        override fun deleteBoolean(key: String) = preferences.deleteBoolean(key)
        override fun deleteInteger(key: String) = preferences.deleteInteger(key)
        override fun deleteString(key: String) = preferences.deleteString(key)
        override fun booleanKeys(): Set<String> = preferences.booleanKeys()
        override fun integerKeys(): Set<String> = preferences.integerKeys()
        override fun stringKeys(): Set<String> = preferences.stringKeys()
    }

    class PersistedObjectStore(private val persistedObject: burp.api.montoya.persistence.PersistedObject) : Store {
        override fun getBoolean(key: String): Boolean? = persistedObject.getBoolean(key)
        override fun setBoolean(key: String, value: Boolean) = persistedObject.setBoolean(key, value)
        override fun getInteger(key: String): Int? = persistedObject.getInteger(key)
        override fun setInteger(key: String, value: Int) = persistedObject.setInteger(key, value)
        override fun getString(key: String): String? = persistedObject.getString(key)
        override fun setString(key: String, value: String) = persistedObject.setString(key, value)
        override fun deleteBoolean(key: String) = persistedObject.deleteBoolean(key)
        override fun deleteInteger(key: String) = persistedObject.deleteInteger(key)
        override fun deleteString(key: String) = persistedObject.deleteString(key)
        override fun booleanKeys(): Set<String> = persistedObject.booleanKeys()
        override fun integerKeys(): Set<String> = persistedObject.integerKeys()
        override fun stringKeys(): Set<String> = persistedObject.stringKeys()
    }

    private val globalStore = PreferencesStore(Burp.Montoya.persistence().preferences())
    private val projectStore = PersistedObjectStore(Burp.Montoya.persistence().extensionData())

    val defaults = mapOf<String, Any>(
        "codegen.depth" to 2,
        "codegen.pad" to 4,
        "integrations.browser.internal" to true,
        "integrations.browser.external.command" to "",
        "integrations.graphiql" to true,
        "integrations.voyager" to true,
        "integrations.playground" to false,
        "integrations.altair" to false,
        "integrations.webserver.lazy" to true,
        "report.json" to true,
        "report.sdl" to true,
        "report.cycles" to true,
        "report.cycles.depth" to 100,
        "report.poi" to true,
        "report.poi.depth" to 2,
        "report.poi.format" to "text",
        "report.poi.type.auth" to true,
        "report.poi.type.privileged" to true,
        "report.poi.type.pii" to true,
        "report.poi.type.payment" to true,
        "report.poi.type.database" to true,
        "report.poi.type.debugging" to true,
        "report.poi.type.files" to true,
        "report.poi.type.deprecated" to true,
        "report.poi.type.custom_scalars" to true,
        "report.poi.custom_keywords" to "",
        "logging.level" to "WARN",
        "proxy.highlight_enabled" to true,
        "proxy.highlight_color" to HighlightColor.BLUE.displayName(),
        "proxy.hijack_introspection" to true,
        "editor.formatting.enabled" to true,
        "editor.formatting.timeout" to 1000, // Cutoff in milliseconds
        "editor.send_to.strip_comments" to true,
    )

    private val hooks = hashMapOf<String, (Any) -> Unit>(
        "logging.level" to { level -> Logger.setLevel(level.toString()) },
    )

    private fun <T> get(key: String, scope: Scope = Scope.EFFECTIVE, getter: (Store, String) -> T?): T? {
        val scopes = when (scope) {
            Scope.EFFECTIVE -> listOf(Scope.PROJECT, Scope.GLOBAL, Scope.DEFAULT)
            Scope.EFFECTIVE_GLOBAL -> listOf(Scope.GLOBAL, Scope.DEFAULT)
            else -> listOf(scope)
        }

        for (currentScope in scopes) {
            @Suppress("UNCHECKED_CAST")
            val output = when (currentScope) {
                Scope.PROJECT -> getter(projectStore, key) as T
                Scope.GLOBAL -> getter(globalStore, key) as T
                Scope.DEFAULT -> defaults[key] as T
                else -> throw Exception("Invalid scope provided to get(): $currentScope")
            }
            if (output != null) {
                Logger.debug("Search $key (scope $currentScope): found with value $output")
                return output
            }
        }

        Logger.debug("Search $key (scope $scope): not found")
        return null
    }

    fun getBoolean(key: String, scope: Scope = Scope.EFFECTIVE): Boolean =
        get(key, scope, Store::getBoolean) ?: false

    fun getInt(key: String, scope: Scope = Scope.EFFECTIVE): Int =
        get(key, scope, Store::getInteger) ?: 0

    fun getString(key: String, scope: Scope = Scope.EFFECTIVE): String =
        get(key, scope, Store::getString) ?: ""

    private fun getAny(key: String, scope: Scope = Scope.EFFECTIVE): Any? {
        for (getter in listOf(Store::getBoolean, Store::getInteger, Store::getString)) {
            try {
                get(key, scope, getter)?.let { return it }
            } catch (e: ClassCastException) {
                // Ignore the exception and try the next type
            }
        }
        return null
    }

    @Suppress("ReplaceCallWithBinaryOperator")
    private fun <T : Any> set(key: String, value: T, scope: Scope = Scope.PROJECT, setter: (Store, String, T) -> Unit) {
        Logger.debug("Setting config value: $key=$value (scope: $scope, type: ${value::class.simpleName})")

        val valueNotUpdated = when (value) {
            is Boolean -> getBoolean(key).equals(value)
            is Int -> getInt(key).equals(value)
            is String -> getString(key).equals(value)
            else -> throw Exception("Invalid value type provided to set(): ${value::class.simpleName}")
        }

        when (scope) {
            Scope.PROJECT -> setter(projectStore, key, value)
            Scope.GLOBAL -> setter(globalStore, key, value)
            else -> throw Exception("Invalid scope provided to set(): $scope")
        }

        hooks[key]?.let {
            if (!valueNotUpdated)
                it(value)
        }
    }

    fun set(key: String, value: Boolean, scope: Scope = Scope.PROJECT) =
        set(key, value, scope, Store::setBoolean)

    fun set(key: String, value: Int, scope: Scope = Scope.PROJECT) =
        set(key, value, scope, Store::setInteger)

    fun set(key: String, value: String, scope: Scope = Scope.PROJECT) =
        set(key, value, scope, Store::setString)

    fun delete(key: String, scope: Scope = Scope.PROJECT) {
        val store = when (scope) {
            Scope.GLOBAL -> globalStore
            Scope.PROJECT -> projectStore
            else -> throw Exception("Invalid scope provided to delete(): $scope")
        }

        val effectiveValue = getAny(key)

        store.deleteBoolean(key)
        store.deleteInteger(key)
        store.deleteString(key)

        hooks[key]?.let {
            val newValue = getAny(key)
            if (effectiveValue != newValue && newValue != null)
                it(newValue)
        }
    }

    private fun items(scope: Scope = Scope.PROJECT): Map<String, Any> =
        when (scope) {
            Scope.DEFAULT -> defaults
            Scope.GLOBAL, Scope.PROJECT -> {
                val store = if (scope == Scope.GLOBAL) globalStore else projectStore

                val booleans = store.booleanKeys().associateWith { store.getBoolean(it) ?: false }
                val integers = store.integerKeys().associateWith { store.getInteger(it) ?: 0 }
                val strings = store.stringKeys().associateWith { store.getString(it) ?: "" }

                booleans + integers + strings
            }

            else -> throw Exception("Invalid scope provided to items(): $scope")
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
