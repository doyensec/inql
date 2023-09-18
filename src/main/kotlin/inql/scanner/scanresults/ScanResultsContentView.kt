package inql.scanner.scanresults

import burp.Burp
import burp.api.montoya.core.ByteArray
import burp.api.montoya.ui.editor.EditorOptions
import inql.graphql.IGQLSchema
import inql.ui.BorderPanel
import inql.ui.GraphQLEditor
import inql.ui.SendFromInqlHandler
import inql.utils.getTextAreaComponent
import java.awt.BorderLayout
import java.awt.CardLayout
import javax.swing.JPanel
import javax.swing.JScrollPane

class ScanResultsContentView(val view: ScanResultsView) : JPanel(CardLayout()) {
    companion object {
        const val RAW_EDITOR_CARD = "RAW_EDITOR_CARD"
        const val GQL_EDITOR_CARD = "GQL_EDITOR_CARD"
    }

    val rawEditor = Burp.Montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
    val gqlEditor = GraphQLEditor(readOnly = true, isIntrospection = true)

    init {
        // Raw payload card
        val rawPayloadCard = BorderPanel(0)
        rawPayloadCard.add(rawEditor.uiComponent(), BorderLayout.CENTER)
        this.add(rawPayloadCard, RAW_EDITOR_CARD)

        // GQLEditor card
        val gqlEditorCard = BorderPanel(0)
        gqlEditorCard.add(JScrollPane(gqlEditor), BorderLayout.CENTER)
        this.add(gqlEditorCard, GQL_EDITOR_CARD)

        (this.layout as CardLayout).show(this, RAW_EDITOR_CARD)
    }

    fun load(elem: IGQLSchema.IGQLElement) {
        this.gqlEditor.setQuery(elem.content())
        (this.layout as CardLayout).show(this, GQL_EDITOR_CARD)
    }

    fun load(elem: String) {
        this.rawEditor.contents = ByteArray.byteArray(elem)
        (this.layout as CardLayout).show(this, RAW_EDITOR_CARD)
    }

    fun load(elem: ByteArray) {
        this.rawEditor.contents = elem
        (this.layout as CardLayout).show(this, RAW_EDITOR_CARD)
    }

    fun setContextMenuHandler(handler: SendFromInqlHandler) {
        handler.addRightClickHandler(rawEditor.getTextAreaComponent())
        handler.addKeyboardShortcutHandler(rawEditor.getTextAreaComponent())
        handler.addRightClickHandler(gqlEditor)
        handler.addKeyboardShortcutHandler(gqlEditor)
    }
}