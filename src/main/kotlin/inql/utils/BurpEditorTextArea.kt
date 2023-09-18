package inql.utils

import burp.api.montoya.ui.editor.Editor
import java.awt.Component
import javax.swing.JComponent
import javax.swing.JTextArea

fun JComponent.findComponentWithName(name: String): Component? {
    for (c in this.components) {
        if (c.name != null && c.name == name) return c
        if (c is JComponent) {
            val depthSearch = c.findComponentWithName(name)
            if (depthSearch != null) return depthSearch
        }
    }
    return null
}

fun Editor.getTextAreaComponent(): JTextArea {
    return (this.uiComponent() as JComponent).findComponentWithName("syntaxTextArea") as JTextArea
}