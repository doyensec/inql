package inql.scanner.scanconfig

import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.awt.event.FocusEvent
import java.awt.event.FocusListener
import java.io.File
import javax.swing.JFileChooser
import javax.swing.filechooser.FileNameExtensionFilter

class ScannerFileChooser(val view: ScanConfigView, var callback: ((file: String?) -> Unit)? = null) : ActionListener,
    FocusListener, JFileChooser() {
    init {
        this.currentDirectory = File(System.getProperty("user.home"))
        this.addChoosableFileFilter(FileNameExtensionFilter("GraphQL Schema", "graphql", "json"))
    }

    // TODO: check if this needs a lock
    fun spawnChooser() {
        when (this.showDialog(view, null)) {
            APPROVE_OPTION -> {
                view.file = this.selectedFile.absolutePath
            }

            else -> view.file = null
        }
        if (callback != null) callback!!(view.file)
    }

    override fun actionPerformed(e: ActionEvent?) {
        this.spawnChooser()
    }

    override fun focusGained(e: FocusEvent?) {
        this.spawnChooser()
        // unfocus to prevent focus loop
        e!!.component.isFocusable = false
        e.component.isFocusable = true
    }

    override fun focusLost(e: FocusEvent?) {
        // Do nothing
    }
}