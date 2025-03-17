package inql.scanner.scanresults

import burp.Burp
import burp.api.montoya.core.ByteArray
import burp.api.montoya.ui.editor.EditorOptions
import inql.ui.BorderPanel
import inql.ui.GraphQLEditor
import inql.ui.SendFromInqlHandler
import inql.utils.getTextAreaComponent
import java.awt.BorderLayout
import java.awt.CardLayout
import javax.swing.JPanel

class ScanResultsContentView(val view: ScanResultsView) : JPanel(CardLayout()) {
    companion object {
        const val RAW_EDITOR_CARD = "RAW_EDITOR_CARD"
        const val GQL_EDITOR_CARD = "GQL_EDITOR_CARD"
    }

    val rawEditor = Burp.Montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
    val gqlEditor = GraphQLEditor(readOnly = true, isIntrospection = true)
    var selectedCard: String = RAW_EDITOR_CARD
        private set

    init {
        // Raw payload card
        val rawPayloadCard = BorderPanel(0)
        rawPayloadCard.add(rawEditor.uiComponent(), BorderLayout.CENTER)
        this.add(rawPayloadCard, RAW_EDITOR_CARD)

        // GQLEditor card
        val gqlEditorCard = BorderPanel(0)
        gqlEditorCard.add(gqlEditor, BorderLayout.CENTER)
        this.add(gqlEditorCard, GQL_EDITOR_CARD)

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

    fun load(elem: String) {
        this.rawEditor.contents = ByteArray.byteArray(elem)
        this.show(RAW_EDITOR_CARD)
    }

    fun load(elem: ByteArray) {
        this.rawEditor.contents = elem
        this.show(RAW_EDITOR_CARD)
    }

    fun getText(): String {
        return when (selectedCard) {
            RAW_EDITOR_CARD -> this.rawEditor.contents.toString()
            GQL_EDITOR_CARD -> this.gqlEditor.getQuery()
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
