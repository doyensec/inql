package inql.utils

import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.JComponent
import java.awt.Component
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.JTextComponent

fun Component.addFocusLostListener(listener: (FocusEvent?) -> Unit) {
    this.addFocusListener(object : FocusAdapter() {
        override fun focusLost(e: FocusEvent?) {
            listener(e)
        }
    })
}

fun JComponent.addKeyPressedListener(listener: (KeyEvent?) -> Unit) {
    this.addKeyListener(object : KeyAdapter() {
        override fun keyPressed(e: KeyEvent?) {
            super.keyPressed(e)
            listener(e)
        }
    })
}

fun JTextComponent.addRemoveUpdateListener(listener: (DocumentEvent?) -> Unit) {
    this.document.addDocumentListener(object : DocumentListener {
        override fun insertUpdate(e: DocumentEvent?) {
            // Do nothing
        }

        override fun removeUpdate(e: DocumentEvent?) {
            listener(e)
        }

        override fun changedUpdate(e: DocumentEvent?) {
            // Do nothing
        }
    })
}
