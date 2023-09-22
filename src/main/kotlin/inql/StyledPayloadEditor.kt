package inql

import burp.Burp
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.RawEditor
import burp.api.montoya.ui.editor.extension.EditorCreationContext
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonSyntaxException
import inql.ui.GraphQLEditor
import inql.ui.SendFromInqlHandler
import inql.utils.GraphQL.Companion.isGraphQLQuery
import inql.utils.JsonPrettifier
import inql.utils.getTextAreaComponent
import java.awt.Component
import java.awt.Font
import javax.swing.JScrollPane
import javax.swing.JSplitPane

class StyledPayloadEditor private constructor(val inql: InQL, private val readOnly: Boolean) :
    ExtensionProvidedHttpRequestEditor {
    companion object {
        class Provider(private val inql: InQL) : HttpRequestEditorProvider {
            override fun provideHttpRequestEditor(creationContext: EditorCreationContext?): ExtensionProvidedHttpRequestEditor {
                return StyledPayloadEditor(
                    inql,
                    (creationContext?.editorMode() ?: EditorMode.DEFAULT) == EditorMode.READ_ONLY,
                )
            }
        }

        private var provider: Provider? = null
        fun getProvider(inql: InQL): Provider {
            if (this.provider == null) this.provider = Provider(inql)
            return this.provider as Provider
        }
    }

    data class EditorState<T>(var hash: Int, var error: Boolean, var backup: T)

    private val gson = Gson()

    private var component: JSplitPane
    private var queryEditor: GraphQLEditor
    private var varsEditor: RawEditor

    private var request: HttpRequest? = null
    private val queryState = EditorState<String>(0, false, "")
    private val varsState = EditorState<JsonObject?>(0, false, null)

    private val contextMenu = EditorSendRequestFromInqlHandler(this)
    private val editorFont: Font
        get() {
            return this.varsEditor.getTextAreaComponent().font
        }

    private var operationName: String? = null
    var query: String
        get() = queryEditor.getQuery()
        set(s) = queryEditor.setQuery(s)
    var vars: JsonObject?
        get() {
            return try {
                gson.fromJson(this.varsEditor.contents.toString(), JsonObject::class.java)
            } catch (_: JsonSyntaxException) {
                null
            }
        }
        set(o) {
            var s = "{}"
            try {
                if (o != null) s = gson.toJson(o)
            } catch (e: Exception) {
                Logger.debug("Failed to deserialize GraphQL variables")
                Logger.debug("Exception: $e")
            }
            val prettified = JsonPrettifier.prettify(s)
            this.varsEditor.contents = ByteArray.byteArray(prettified)
        }

    init {
        this.queryEditor = GraphQLEditor(readOnly)

        if (readOnly) {
            this.varsEditor = Burp.Montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
        } else {
            this.varsEditor = Burp.Montoya.userInterface().createRawEditor()
        }

        this.component =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(this.queryEditor), this.varsEditor.uiComponent())
        this.component.setDividerLocation(0.5)
        this.component.resizeWeight = 0.75
        this.component.isOneTouchExpandable = true

        // Add context menu handler
        this.contextMenu.addRightClickHandler(this.queryEditor)
        this.contextMenu.addKeyboardShortcutHandler(this.queryEditor)
    }

    private fun refreshFont() {
        // This is needed because we take the font from the varsEditor and
        //  Burp doesn't set the correct font until the editor needs to be displayed
        this.queryEditor.setFontInHTML(this.editorFont)
    }

    override fun setRequestResponse(requestResponse: HttpRequestResponse) {
        refreshFont()
        this.request = requestResponse.request()
        lateinit var body: JsonObject
        val json_body = requestResponse.request().bodyToString()
        try {
            body = gson.fromJson(json_body, JsonObject::class.java)
        } catch (e: Exception) {
            Logger.error("Failed to deserialize request body")
            if (!this.queryState.error) this.queryState.backup = this.query
            if (!this.varsState.error) this.varsState.backup = this.vars

            // Mark errors and backup old values (unless these are repeated errors - don't overwrite backups)
            this.queryState.error = true
            this.varsState.error = true

            // Show the message about an error:
            this.queryEditor.text = "There was an error during JSON deserialization."
            this.vars = null
            return
        }

        // Reset backups and error info if JSON parsed successfully
        this.queryState.error = false
        this.varsState.error = false
        this.queryState.backup = ""
        this.varsState.backup = null

        this.operationName = null
        // Variables are optional, can be absent, {} and null
        if (body.has("operation_name")) this.operationName = body.get("operation_name").asString

        // Calculate new hashes (note that we need to re-read values as they might have changed due to normalization)
        this.query = body.get("query").asString
        this.vars =
            if (body.has("variables") && body.get("variables").isJsonObject) body.get("variables").asJsonObject else null

        this.queryState.hash = this.query.hashCode()
        this.varsState.hash = this.vars.hashCode()

        this.request = requestResponse.request()
    }

    override fun isEnabledFor(requestResponse: HttpRequestResponse): Boolean {
        return isGraphQLQuery(requestResponse.request().bodyToString())
    }

    override fun caption(): String {
        return "GraphQL"
    }

    override fun uiComponent(): Component {
        return this.component
    }

    override fun selectedData(): Selection? {
        return null
    }

    override fun isModified(): Boolean {
        return this.queryState.hash != this.query.hashCode() || this.varsState.hash != this.vars.hashCode()
    }

    override fun getRequest(): HttpRequest {
        var query = this.query
        if (this.queryState.error) {
            if (this.queryState.hash != this.query.hashCode()) {
                // Query has been modified, assume that user has fixed it
                this.queryState.error = false
                this.queryState.backup = ""
            } else {
                query = this.queryState.backup
            }
        }

        var vars = this.vars
        if (this.varsState.error) {
            if (this.varsState.hash != this.vars.hashCode()) {
                // Query has been modified, assume that user has fixed it
                this.varsState.error = false
                this.varsState.backup = null
            } else {
                vars = this.varsState.backup
            }
        }

        var body = JsonObject().also { it.addProperty("query", query) }
        if (vars != null) body.add("variables", vars)
        if (operationName != null) body.addProperty("operationName", operationName)

        val req = if (this.request != null) this.request else HttpRequest.httpRequest()
        return req!!.withBody(gson.toJson(body))
    }

    class EditorSendRequestFromInqlHandler(val editor: StyledPayloadEditor) : SendFromInqlHandler(editor.inql, true) {
        override fun getRequest(): HttpRequest {
            return editor.getRequest()
        }
    }
}
