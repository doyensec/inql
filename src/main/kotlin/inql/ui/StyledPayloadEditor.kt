package inql.ui

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
import inql.InQL
import inql.Logger
import inql.graphql.GraphQLRequestPayload
import inql.graphql.GraphQLRequestTransformer
import inql.utils.GraphQLEditorSearchPanel
import inql.utils.JsonPrettifier
import inql.utils.getTextAreaComponent
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Font
import javax.swing.JSplitPane

class StyledPayloadEditor private constructor(val inql: InQL, readOnly: Boolean) :
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
            if (provider == null) provider = Provider(inql)
            return provider as Provider
        }
    }

    data class EditorState<T>(var hash: Int, var error: Boolean, var backup: T)

    private val gson = Gson()

    private var component: JSplitPane
    private var queryEditor: GraphQLEditor
    private var varsEditor: RawEditor

    private var request: HttpRequest? = null
    private var graphQLPayload: GraphQLRequestPayload? = null
    private val transportState = GraphQLRequestEditorTransportState()
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
        val gqlEditorCard = BorderPanel(0)
        val gqlEditorSearchPanel = GraphQLEditorSearchPanel(this.queryEditor.textPane)

        gqlEditorCard.add(queryEditor, BorderLayout.CENTER)
        gqlEditorCard.add(gqlEditorSearchPanel, BorderLayout.SOUTH)

        if (readOnly) {
            this.varsEditor = Burp.Montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
        } else {
            this.varsEditor = Burp.Montoya.userInterface().createRawEditor()
        }

        this.component =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, gqlEditorCard, this.varsEditor.uiComponent())
        this.component.setDividerLocation(0.5)
        this.component.resizeWeight = 0.75
        this.component.isOneTouchExpandable = true

        // Add context menu handler
        this.contextMenu.addRightClickHandler(this.queryEditor.textPane)
        this.contextMenu.addKeyboardShortcutHandler(this.queryEditor.textPane)
    }

    override fun setRequestResponse(requestResponse: HttpRequestResponse) {
        transportState.onSetRequestResponse(
            incoming = requestResponse.request(),
            isModified = isModified(),
            onLoad = { loaded ->
                this.queryState.error = false
                this.varsState.error = false
                this.queryState.backup = ""
                this.varsState.backup = null

                this.graphQLPayload = loaded.payload
                this.operationName = loaded.operationName
                this.query = loaded.query
                this.vars = loaded.variables

                this.queryState.hash = this.query.hashCode()
                this.varsState.hash = this.varsEditor.contents.toString().hashCode()
                this.request = requestResponse.request()
            },
            onParseError = {
                Logger.error("Failed to parse GraphQL request")
                if (!this.queryState.error) this.queryState.backup = this.query
                if (!this.varsState.error) this.varsState.backup = this.vars

                this.queryState.error = true
                this.varsState.error = true

                this.queryEditor.setPlaintext("Could not parse GraphQL parameters from this request.")
                this.vars = null
            },
        )
    }

    override fun isEnabledFor(requestResponse: HttpRequestResponse): Boolean {
        return GraphQLRequestTransformer.parsePayload(requestResponse.request()) != null
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
        return this.queryState.hash != this.query.hashCode() ||
            this.varsState.hash != this.varsEditor.contents.toString().hashCode()
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

        val variablesJson = vars?.let { gson.toJson(it) }
        val payload = graphQLPayload?.withFirstOperation(
            query = query,
            variables = variablesJson,
            operationName = operationName,
        ) ?: GraphQLRequestPayload.single(
            query = query,
            variables = variablesJson,
            operationName = operationName,
        )

        val built = transportState.buildRequest(payload)
        this.request = built
        this.queryState.hash = query.hashCode()
        this.varsState.hash = this.varsEditor.contents.toString().hashCode()
        return built
    }

    class EditorSendRequestFromInqlHandler(val editor: StyledPayloadEditor) : SendFromInqlHandler(editor.inql, true) {
        override fun getRequest(): HttpRequest {
            return editor.getRequest()
        }

        override fun getText(): String {
            return editor.query
        }
    }
}
