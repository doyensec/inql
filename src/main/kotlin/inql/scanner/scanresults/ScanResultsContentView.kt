package inql.scanner.scanresults

import burp.Burp
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.editor.EditorOptions
import inql.graphql.scanners.CycleResult
import inql.scanner.ScanResult
import inql.ui.BorderPanel
import inql.ui.GraphQLEditor
import inql.ui.SendFromInqlHandler
import inql.utils.GraphQLEditorSearchPanel
import inql.utils.getTextAreaComponent
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import javax.swing.JPanel

class ScanResultsContentView(val view: ScanResultsView) : JPanel(CardLayout()) {
    companion object {
        const val RAW_EDITOR_CARD = "RAW_EDITOR_CARD"
        const val GQL_EDITOR_CARD = "GQL_EDITOR_CARD"
        const val CYCLE_CARD = "CYCLE_CARD"
        const val SCHEMA_CORRECTIONS_CARD = "SCHEMA_CORRECTIONS_CARD"
        const val REQUEST_TEMPLATE_CARD = "REQUEST_TEMPLATE_CARD"
    }

    val requestTemplateEditor = Burp.Montoya.userInterface().createHttpRequestEditor()
    val rawEditor = Burp.Montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
    val gqlEditor = GraphQLEditor(readOnly = true, isIntrospection = true)
    private val cyclePanel = CycleDetectionPanel(view)
    private var schemaCorrectionsPanel: SchemaCorrectionsPanel? = null
    var selectedCard: String = RAW_EDITOR_CARD
        private set

    init {
        // Raw payload card
        val rawPayloadCard = BorderPanel(0)
        rawPayloadCard.add(rawEditor.uiComponent(), BorderLayout.CENTER)
        this.add(rawPayloadCard, RAW_EDITOR_CARD)

        // GQLEditor card
        val gqlEditorCard = BorderPanel(0)
        val gqlEditorSearchPanel = GraphQLEditorSearchPanel(this.gqlEditor.textPane)
        gqlEditorCard.add(gqlEditor, BorderLayout.CENTER)
        gqlEditorCard.add(gqlEditorSearchPanel, BorderLayout.SOUTH)
        this.add(gqlEditorCard, GQL_EDITOR_CARD)

        // Cycle Detection card
        this.add(cyclePanel, CYCLE_CARD)

        val requestTemplateCard = BorderPanel(0)
        requestTemplateCard.add(requestTemplateEditor.uiComponent(), BorderLayout.CENTER)
        this.add(requestTemplateCard, REQUEST_TEMPLATE_CARD)
        requestTemplateEditor.getTextAreaComponent().addFocusListener(object : FocusAdapter() {
            override fun focusLost(e: FocusEvent) {
                view.commitRequestTemplateEdits()
            }
        })

        this.show(RAW_EDITOR_CARD)
    }

    private fun show(card: String) {
        this.selectedCard = card
        (this.layout as CardLayout).show(this, card)
    }

    fun load(elem: GQLQueryElement) {
        this.gqlEditor.setQuery(elem.content())
        this.show(GQL_EDITOR_CARD)
    }

    fun load(elem: GQLTypeElement) {
        this.gqlEditor.setPlaintext(elem.content())
        this.show(GQL_EDITOR_CARD)
    }

    fun loadRequestTemplate(template: HttpRequest) {
        this.requestTemplateEditor.request = template
        this.show(REQUEST_TEMPLATE_CARD)
    }

    fun currentRequestTemplate(): HttpRequest = this.requestTemplateEditor.request.withBody("")

    fun load(elem: String) {
        this.rawEditor.contents = ByteArray.byteArray(elem)
        this.show(RAW_EDITOR_CARD)
    }

    fun load(elem: ByteArray) {
        this.rawEditor.contents = elem
        this.show(RAW_EDITOR_CARD)
    }

    fun loadSchemaCorrections(
        scanResult: ScanResult,
        focusArgumentTypesTab: Boolean = false,
        argumentParentType: String? = null,
        argumentFieldName: String? = null,
        argumentName: String? = null,
        argumentType: String? = null,
    ) {
        val fresh = view.getScanResult(scanResult.uuid) ?: scanResult
        val panel = schemaCorrectionsPanel
        if (panel == null) {
            schemaCorrectionsPanel = SchemaCorrectionsPanel(view, fresh).also {
                this.add(it, SCHEMA_CORRECTIONS_CARD)
            }
        } else {
            panel.load(fresh)
        }
        if (focusArgumentTypesTab) {
            schemaCorrectionsPanel?.focusArgumentTypesTab(
                parentType = argumentParentType,
                fieldName = argumentFieldName,
                argumentName = argumentName,
                argumentType = argumentType,
            )
        }
        this.show(SCHEMA_CORRECTIONS_CARD)
    }

    fun loadCycleLoading() {
        this.cyclePanel.showLoading()
        this.show(CYCLE_CARD)
    }

    fun loadCycleResults(scanResult: ScanResult, cycles: List<CycleResult>) {
        this.cyclePanel.showResults(scanResult, cycles)
        this.show(CYCLE_CARD)
    }

    fun release() {
        view.commitRequestTemplateEdits()
        gqlEditor.clear()
        rawEditor.contents = ByteArray.byteArray("")
        cyclePanel.release()
        schemaCorrectionsPanel = null
    }

    fun getText(): String {
        return when (selectedCard) {
            RAW_EDITOR_CARD -> this.rawEditor.contents.toString()
            GQL_EDITOR_CARD -> this.gqlEditor.getQuery()
            CYCLE_CARD -> this.cyclePanel.getExportText()
            SCHEMA_CORRECTIONS_CARD -> schemaCorrectionsPanel?.let { "" } ?: ""
            REQUEST_TEMPLATE_CARD -> this.requestTemplateEditor.request.toString()
            else -> ""
        }
    }

    fun setContextMenuHandler(handler: SendFromInqlHandler) {
        handler.addRightClickHandler(rawEditor.getTextAreaComponent())
        handler.addKeyboardShortcutHandler(rawEditor.getTextAreaComponent())
        handler.addRightClickHandler(gqlEditor.textPane)
        handler.addKeyboardShortcutHandler(gqlEditor.textPane)
    }
}
