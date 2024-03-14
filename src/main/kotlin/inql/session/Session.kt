package inql.session

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.persistence.PersistedObject
import com.charleskorn.kaml.*
import com.google.gson.JsonParseException
import inql.Config
import inql.Logger
import inql.graphql.GQLSchemaMemoryBackedImpl
import inql.graphql.IGQLSchema
import inql.graphql.sendIntrospectionQuery
import inql.savestate.BurpDeserializable
import inql.savestate.SavesDataToProject
import inql.savestate.loadObjectFromProjectFile
import inql.scanner.ScannerTab
import inql.utils.withUpsertedHeaders
import isValidUrl
import kotlinx.serialization.Serializable
import java.net.URI

/*
    Session configuration is displayed as YAML in the section "Session Config" of the Scanner tab, such as:

        ```yaml
        # Unique identifier of the GraphQL scan
        session_id: myapp_scan_1

        # Base URL for the GraphQL endpoint, used in query generation
        graphql_endpoint: https://api.example.com/graphql

        # Settings that affect the InQL UI
        ui_settings:
            # Maximum depth of generated queries
            max_query_depth: 5

            # Padding for generated queries
            padding: 2

            # Enable syntax highlighting in the UI
            enable_syntax_highlighting: true

        # Settings that affect all network requests going through Burp with:
        #   1. URL matching `graphql_endpoint` or `request_settings.extra_endpoints`
        #   2. X-Burp-InQL header set to `sessionId`
        #   3. Request is a GraphQL query or mutation
        request_settings:
            # Extra endpoints to match, in addition to the main `graphql_endpoint` above
            extra_endpoints:
                - https://example.inql/graphql

            # Answer introspection requests via cached schema (e.g. if offline or introspection is disabled on the server)
            hijack_introspection: true

            # HTTP headers
            headers:
                # Headers to add if not present in the original request
                add_if_missing:
                    - Example-InQL-Header: some header value here

                # Headers to add if not present or overwrite if present (matching is non-case-sensitive)
                overwrite:
                    - Example-InQL-Header: another header value here

            # Default values for GraphQL variables
            default_variable_values:
                ExampleInQLVariable: "some value here"
        ```
 */

class Session private constructor(var sessionId: String, var graphqlEndpoint: String) : SavesDataToProject,
    BurpDeserializable {
    var uiSettings: UiSettings = UiSettings.default()
    var requestSettings: RequestSettings = RequestSettings.default()
    private lateinit var scannerTab: ScannerTab
    lateinit var schema: SessionSchema
    private val overwriteHeadersMap: MutableMap<String, Pair<String, String>> = mutableMapOf()
    var gqlSchema: IGQLSchema? = null

    companion object {
       private val yamlEncoder = Yaml(configuration = YamlConfiguration(
           breakScalarsAt = 120,
           singleLineStringStyle = SingleLineStringStyle.PlainExceptAmbiguous,
           yamlNamingStrategy = YamlNamingStrategy.SnakeCase
       ))

        // Two main methods called by ScannerTab.launchScan -> ScannerTab.analyze
        fun createWithLocalSchema(scannerTab: ScannerTab, localSchema: String): Session {
            val session = createWithYaml(scannerTab.sessionConfig)
            session.scannerTab = scannerTab
            session.processLocalSchema(localSchema)
            return session
        }

        fun createWithRemoteSchema(scannerTab: ScannerTab): Session {
            val session = createWithYaml(scannerTab.sessionConfig)
            session.scannerTab = scannerTab
            session.processRemoteSchema()
            return session
        }

        /**
         * Creates a new Session object with values from a YAML string. Used when initiating a scan from a Scanner tab.
         *
         * @param yaml the YAML string to parse
         * @return A new Session object with values from the YAML string.
         * @throws IllegalArgumentException if the YAML string is invalid
         */
        private fun createWithYaml(yaml: String): Session {
            val sessionYaml = yamlEncoder.decodeFromString(SessionYaml.serializer(), yaml)

            if (!isValidUrl(sessionYaml.graphqlEndpoint)) {
                throw IllegalArgumentException("Invalid URL: ${sessionYaml.graphqlEndpoint}")
            }

            if (sessionYaml.sessionId.isBlank()) {
                sessionYaml.sessionId = SessionManager.newSessionId(sessionYaml.graphqlEndpoint, sessionYaml.sessionId)
            }

            val session = Session(sessionYaml.sessionId, sessionYaml.graphqlEndpoint)
            session.updateFromYaml(yaml)

            return session
        }

        /**
         * Creates an empty session template as a YAML string. Used when creating a new Scanner tab without HTTP request.
         */
        fun createEmptyTemplate(): String {
            val sessionYaml = SessionYaml(
                sessionId = "",
                graphqlEndpoint = "",
                uiSettings = UiSettings.default(),
                requestSettings = RequestSettings.default()
            )
            return yamlEncoder.encodeToString(SessionYaml.serializer(), sessionYaml)
        }

        fun updateTemplateWithUrl(yaml: String, url: String): String {
            val sessionYaml = yamlEncoder.decodeFromString(SessionYaml.serializer(), yaml)
            if (sessionYaml.graphqlEndpoint == url) {
                return yaml
            }

            sessionYaml.graphqlEndpoint = url
            sessionYaml.sessionId = SessionManager.newSessionId(sessionYaml.graphqlEndpoint, sessionYaml.sessionId)

            return yamlEncoder.encodeToString(SessionYaml.serializer(), sessionYaml)
        }

        fun updateTemplateWithHeaders(yaml: String, headers: List<HttpHeader>): String {
            val sessionYaml = yamlEncoder.decodeFromString(SessionYaml.serializer(), yaml)

            val originalHeaders = sessionYaml.requestSettings.headers.addIfMissing.toMutableList()
            headers.forEach { newHeader ->
                // Remove all occurrences of the header with the same name
                originalHeaders.removeAll { oldHeader ->
                    oldHeader.keys.first().lowercase() == newHeader.name().lowercase()
                }

                // Add the new header to the end of the original list
                originalHeaders.add(mapOf(newHeader.name() to newHeader.value()))
            }

            // Update the headers in the sessionYaml object
            sessionYaml.requestSettings.headers.addIfMissing = originalHeaders

            return yamlEncoder.encodeToString(SessionYaml.serializer(), sessionYaml)
        }

        fun getUrlOutOfTemplate(yaml: String): String? {
            return try {
                val sessionYaml = yamlEncoder.decodeFromString(SessionYaml.serializer(), yaml)
                sessionYaml.graphqlEndpoint
            } catch (e: Exception) {
                null
            }
        }

        fun getSessionIdOutOfTemplate(yaml: String): String? {
            return try {
                val sessionYaml = yamlEncoder.decodeFromString(SessionYaml.serializer(), yaml)
                sessionYaml.sessionId
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Deserializes a Session object from a PersistedObject (Burp's project file).
         *
         * @param sessionId the session id
         * @return A new Session object with values from the PersistedObject.
         */
        fun restoreFromBurpProject(sessionId: String): Session? {
            val obj = loadObjectFromProjectFile("Session.$sessionId")
            if (obj == null) {
                Logger.error("No save state with key Session.$sessionId found in this project file")
                return null
            }
            return try {
                val session = Session(obj.getString("sessionId"), obj.getString("graphqlEndpoint"))
                session.burpDeserialize(obj)
                session
            } catch (e: Exception) {
                Logger.error("Failed deserializing session with id $sessionId")
                Logger.error(e.stackTraceToString())
                null
            }
        }
    }

    private fun processLocalSchema(localSchema: String) {
        try {
            this.schema = SessionSchema(localSchema, SchemaTools.jsonToSdl(localSchema))
        } catch (e: JsonParseException) {
            // The file is not a valid JSON, assume it's an SDL schema
            this.schema = SessionSchema(SchemaTools.sdlToJson(localSchema), localSchema)
        }
    }

    private fun processRemoteSchema() {
        val jsonSchema = sendIntrospectionQuery(this.graphqlEndpoint, resolveHeaders())
        if (jsonSchema != null) {
            this.processLocalSchema(jsonSchema)
        } else {
            throw IllegalArgumentException("Failed to retrieve schema from ${this.graphqlEndpoint}")
        }
    }

    val requestTemplate: HttpRequest
        get() {
            val url = URI.create(this.graphqlEndpoint)
            Logger.info("URL: $url, host: ${url.host}, path: ${url.path}")
            return HttpRequest.httpRequest()
                .withService(
                    HttpService.httpService(this.graphqlEndpoint) )
                .withMethod("POST")
                .withPath(url.path)
                .withUpsertedHeaders(
                    resolveHeaders().associate { it.name() to it.value() } )
        }

    private fun resolveHeaders(headers: List<HttpHeader> = listOf()): List<HttpHeader> {
        val resolvedHeaders = mutableListOf<HttpHeader>()
        val processedHeaders = mutableSetOf<String>()

        // Ensure Host header is always the first header
        val urlHost = URI.create(this.graphqlEndpoint).host
        resolvedHeaders.add(HttpHeader.httpHeader("Host", urlHost))
        processedHeaders.add("host")

        // process  existing headers
        headers.forEach { header ->
            val name = header.name()
            val lowerCaseName = name.lowercase()
            if (lowerCaseName != "host") {
                val value = this.overwriteHeadersMap[lowerCaseName]?.second ?: header.value()
                resolvedHeaders.add(HttpHeader.httpHeader(name, value))
                processedHeaders.add(lowerCaseName)
            }
        }

        // Add missing headers from overwrite list
        this.requestSettings.headers.overwrite.forEach { headerMap ->
            headerMap.entries.firstOrNull()?.let { (k, v) ->
                if (k.lowercase() !in processedHeaders) {
                    resolvedHeaders.add(HttpHeader.httpHeader(k, v))
                }
            }
        }

        // Add missing headers from addIfMissing list
        this.requestSettings.headers.addIfMissing.forEach { headerMap ->
            headerMap.entries.firstOrNull()?.let { (k, v) ->
                if (k.lowercase() !in processedHeaders) {
                    resolvedHeaders.add(HttpHeader.httpHeader(k, v))
                }
            }
        }

        return resolvedHeaders
    }

    /**
     * Updates the session configuration from a YAML string.
     *
     * @param yaml the YAML string to parse
     * @throws IllegalArgumentException if the YAML string is invalid
     */
    fun updateFromYaml(yaml: String) {
        val sessionYaml = yamlEncoder.decodeFromString(SessionYaml.serializer(), yaml)

        if (this.graphqlEndpoint != sessionYaml.graphqlEndpoint) {
            if (isValidUrl(sessionYaml.graphqlEndpoint)) {
                this.graphqlEndpoint = sessionYaml.graphqlEndpoint
            } else {
                throw IllegalArgumentException("Invalid URL: ${sessionYaml.graphqlEndpoint}")
            }
        }

        this.uiSettings = sessionYaml.uiSettings
        this.requestSettings = sessionYaml.requestSettings
        this.updateOverwriteHeadersMap()

        if (sessionYaml.sessionId.isBlank()) {
            this.sessionId = SessionManager.newSessionId(this.graphqlEndpoint, this.sessionId)
        } else if (this.sessionId != sessionYaml.sessionId) {
            SessionManager.updateSessionId(this.sessionId, sessionYaml.sessionId)
            // FIXME: Inform Scanner Tab to update the session id label
        } else {
            // FIXME: Why is this in the 'else' clause?
            this.saveToProjectFileAsync()
        }
    }

    private fun updateOverwriteHeadersMap() {
        this.overwriteHeadersMap.clear()
        this.requestSettings.headers.overwrite.forEach { headerMap ->
            headerMap.entries.firstOrNull()?.let { (k, v) ->
                this.overwriteHeadersMap[k.lowercase()] = Pair(k, v)
            }
        }
    }

    fun analyze() {
        try {
            this.gqlSchema = GQLSchemaMemoryBackedImpl(this)
        } catch (e: Exception) {
            Logger.error("Failed to parse schema for session $sessionId")
            Logger.error(e.stackTraceToString())
            throw RuntimeException("Failed to deserialize JSON schema")
        }
        this.scannerTab.setTabTitle(this.sessionId)
    }

    @Serializable
    data class SessionYaml(
        // This class is used to read and write the session configuration to a YAML file
        @YamlComment("Unique identifier of the GraphQL scan")
        var sessionId: String,
        @YamlComment("Base URL for the GraphQL endpoint, used in query generation")
        var graphqlEndpoint: String,
        @YamlComment("Settings that affect the InQL UI")
        val uiSettings: UiSettings,
        @YamlComment(
            "Settings that affect all network requests going through Burp with:",
            "1. URL matching `graphql_endpoint` or `request_settings.extra_endpoints`",
            "2. X-Burp-InQL header set to `session_id`",
            "3. Request is a GraphQL query or mutation",
        )
        val requestSettings: RequestSettings,
    )

    @Serializable
    data class UiSettings(
        @YamlComment("Maximum depth of generated queries")
        var maxQueryDepth: Int,
        @YamlComment("Padding for generated queries")
        var padding: Int,
        @YamlComment("Enable syntax highlighting in the UI")
        var enableSyntaxHighlighting: Boolean
    ) {
        companion object {
            fun default(): UiSettings {
                val config = Config.getInstance()
                return UiSettings(
                    maxQueryDepth = config.getInt("codegen.depth"),
                    padding = config.getInt("codegen.pad"),
                    enableSyntaxHighlighting = config.getBoolean("editor.formatting.enabled")
                ) } } }

    @Serializable
    data class RequestSettings(
        @YamlComment("Extra endpoints to match, in addition to the main `graphql_endpoint` above")
        var extraEndpoints: List<String>,
        @YamlComment("Answer introspection requests via cached schema (e.g. if offline or introspection is disabled on the server)")
        var hijackIntrospection: Boolean,
        @YamlComment("HTTP headers")
        var headers: HeaderSettings,
        @YamlComment("Default values for GraphQL variables")
        var defaultVariableValues: MutableMap<String, String>,
    ) {
        companion object {
            fun default(): RequestSettings {
                val config = Config.getInstance()
                return RequestSettings(
                    extraEndpoints = listOf(),
                    hijackIntrospection = config.getBoolean("proxy.hijackIntrospection"),
                    headers = HeaderSettings.default(),
                    defaultVariableValues = mutableMapOf("ExampleInQLVariable" to "some value here")
                ) } } }

    @Serializable
    data class HeaderSettings(
        @YamlComment("Headers to add if not present in the original request")
        var addIfMissing: MutableList<Map<String, String>> = mutableListOf(),
        @YamlComment("Headers to add if not present or overwrite if present (matching is non-case-sensitive)")
        var overwrite: MutableList<Map<String, String>> = mutableListOf(),
    ) {
        companion object {
            fun default(): HeaderSettings {
                return HeaderSettings(
                    addIfMissing = mutableListOf(mapOf("Content-Type" to "application/json")),
                    overwrite = mutableListOf(),
                ) } } }

    // Technically both should be interchangeable, but either one might have been the source of truth, so we keep both
    // for now. Conversion between the two is done in the SchemaTools, and it might not be perfect.
    // Currently, JSON is used for generating queries through GQLSpection, while SDL is used for answering introspection
    // queries (if hijackIntrospection is enabled).
    data class SessionSchema(
        val json: String,
        val sdl: String,
    )

    fun toYaml(): String {
        return yamlEncoder.encodeToString(
            SessionYaml.serializer(),
            SessionYaml(this.sessionId, this.graphqlEndpoint, this.uiSettings, this.requestSettings),
        )
    }

    override fun burpDeserialize(obj: PersistedObject) {
        Logger.debug("Deserializing session $sessionId")
        this.uiSettings = obj.getChildObject("uiSettings")?.let {
            this.uiSettings.copy(
                maxQueryDepth = it.getInteger("maxQueryDepth"),
                padding = it.getInteger("padding"),
                enableSyntaxHighlighting = it.getBoolean("enableSyntaxHighlighting"),
            )
        } ?: UiSettings.default()
        this.requestSettings = obj.getChildObject("requestSettings")?.let { persistedObject ->
            RequestSettings(
                extraEndpoints = persistedObject.getStringList("extraEndpoints").orEmpty().toMutableList(),
                hijackIntrospection = persistedObject.getBoolean("hijackIntrospection"),
                headers = persistedObject.getChildObject("headers")?.let { persistedHeaders ->
                    HeaderSettings(
                        addIfMissing = persistedHeaders.getStringList("addIfMissing").orEmpty().map {
                            val (k, v) = it.split(":", limit = 2)
                            mapOf(k to v)
                        }.toMutableList(),
                        overwrite = persistedHeaders.getStringList("overwrite").orEmpty().map {
                            val (k, v) = it.split(":", limit = 2)
                            mapOf(k to v)
                        }.toMutableList()
                    )
                } ?: HeaderSettings.default(),
                defaultVariableValues = persistedObject.getChildObject("defaultVariableValues")?.let {
                    it.stringKeys().associateWith { k -> it.getString(k) }
                }?.toMutableMap() ?: mutableMapOf()
            )
        } ?: RequestSettings.default()
    }

    override val saveStateKey: String
        get() = "Session.$sessionId"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject>? = null

    override fun burpSerialize(): PersistedObject {
        Logger.debug("Serializing session $sessionId")
        val obj = PersistedObject.persistedObject()

        obj.setString("sessionId", this.sessionId)
        obj.setString("graphqlEndpoint", this.graphqlEndpoint)

        obj.setChildObject("uiSettings", PersistedObject.persistedObject().also {
            it.setInteger("maxQueryDepth", this.uiSettings.maxQueryDepth)
            it.setInteger("padding", this.uiSettings.padding)
            it.setBoolean("enableSyntaxHighlighting", this.uiSettings.enableSyntaxHighlighting)
        })

        obj.setChildObject("requestSettings", PersistedObject.persistedObject().also { persistedSettings ->
            persistedSettings.setStringList("extraEndpoints", listToPersistedList(this.requestSettings.extraEndpoints))
            persistedSettings.setBoolean("hijackIntrospection", this.requestSettings.hijackIntrospection)
            persistedSettings.setChildObject("headers", PersistedObject.persistedObject().also { persistedHeaders ->
                persistedHeaders.setStringList("addIfMissing",
                    listToPersistedList(this.requestSettings.headers.addIfMissing.map { "${it.keys.first()}:${it.values.first()}" }))
                persistedHeaders.setStringList("overwrite",
                    listToPersistedList(this.requestSettings.headers.overwrite.map { "${it.keys.first()}:${it.values.first()}" }))
            })
            persistedSettings.setChildObject("defaultVariableValues", PersistedObject.persistedObject().also {
                this.requestSettings.defaultVariableValues.forEach { (k, v) -> it.setString(k, v) }
            })
        })
        return obj
    }

    private fun listToPersistedList(list: List<String>): PersistedList<String> {
        val persistedList = PersistedList.persistedStringList()
        list.forEach { persistedList.add(it) }
        return persistedList
    }

    override fun toString(): String {
        return "Session(sessionId='$sessionId', graphqlEndpoint=$graphqlEndpoint)"
    }
}
