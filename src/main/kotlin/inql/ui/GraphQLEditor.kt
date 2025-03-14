package inql.ui

import burp.Burp
import burp.api.montoya.ui.editor.RawEditor
import inql.Config
import inql.Logger
import inql.graphql.formatting.Formatter
import inql.graphql.formatting.Style
import inql.utils.getTextAreaComponent
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.apache.commons.text.StringEscapeUtils
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Font
import java.awt.event.ComponentAdapter
import java.util.concurrent.CancellationException
import javax.swing.*
import javax.swing.text.SimpleAttributeSet
import java.awt.event.ComponentEvent
import javax.swing.text.AttributeSet
import javax.swing.text.StyleConstants

class GraphQLEditor(readOnly: Boolean = false, val isIntrospection: Boolean = false) : JPanel(BorderLayout()) {

    private val formatter = Formatter(false, 4, asHTML = true, isIntrospection = isIntrospection)
    private val formattingCoroutineScope = CoroutineScope(Dispatchers.Default)
    private var runningJob: Job? = null
    private val timeout = Config.getInstance().getInt("editor.formatting.timeout") ?: 1000
    private val mutex = Mutex() // Prevent writing from multiple coroutines at the same time

    private val normalTextStyle = SimpleAttributeSet()

    private val textPane = JTextPane().also {
        it.isEditable = !readOnly
        it.editorKit = WrapEditorKit()
    }

    private val textPaneContainer = JPanel().also {
        it.layout = BoxLayout(it, BoxLayout.PAGE_AXIS)
        it.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
        it.add(textPane, BorderLayout.CENTER)
    }

    private val scrollPane = JScrollPane(textPaneContainer).also {
        it.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        it.verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
    }

    class TextPaneComponentAdapter(val callback: ()->Unit): ComponentAdapter() {
        override fun componentResized(e: ComponentEvent?) {
            callback()
        }
    }

    private fun updateComponentSize() {
        this.textPaneContainer.preferredSize = Dimension(this.scrollPane.width, textPane.preferredSize.height)
    }

    init {
        this.scrollPane.addComponentListener(TextPaneComponentAdapter { this.updateComponentSize() })
        this.add(scrollPane)
    }

    fun setFontInHTML(f: Font) {
        this.font = f
        val doc = this.textPane.styledDocument
        val newFont = SimpleAttributeSet().also {
            StyleConstants.setFontFamily(it, f.family)
            StyleConstants.setFontSize(it, f.size)
        }

        doc.setCharacterAttributes(0, doc.length, newFont, false)
    }

    fun getQuery(): String {
        val doc = this.textPane.styledDocument
        val content = doc.getText(0, doc.length)
        return content
    }

    fun setHTML(content: String) {
        try {
            this.textPane.styledDocument.insertString(0, content, normalTextStyle)
        } catch (e: OutOfMemoryError) {
            this.textPane.styledDocument.insertString(0,"Request too large to display. Out of memory: ${e.message}", normalTextStyle)
        }
    }

    fun setQuery(s: String) {
        if (this.runningJob != null) {
            this.runningJob!!.cancel()
            this.runningJob = null
        }
        val job = this.formattingCoroutineScope.launch { this@GraphQLEditor.format(s) }
        this.runningJob = job
        this.formattingCoroutineScope.launch { this@GraphQLEditor.writeOriginal(job, s) }
        this.formattingCoroutineScope.launch { this@GraphQLEditor.timeout(job, this@GraphQLEditor.timeout) }
    }


    private suspend fun timeout(job: Job, timeout: Int) {
        delay(timeout.toLong())
        mutex.withLock {    // If the mutex is locked, the formatting coroutine may be already writing the results, no point in cancelling now
            if (job.isActive) {
                job.cancel()
            }
        }
    }

    // Write the unformatted string after some delay (to avoid the screen "blinking" too much)
    private suspend fun writeOriginal(job: Job, s: String) {
        delay(150)
        if (mutex.tryLock()) { // If the mutex is already locked, abort as something else is being written already
            if (job.isActive) {
                this.textPane.styledDocument.insertString(0, s, normalTextStyle)
            }
            mutex.unlock()
        }
    }

    suspend fun format(s: String) {
        try {
            val text = formatter.formatAsStyledDoc(s)
            mutex.withLock {
                this.textPane.styledDocument = text
                this.setFontInHTML(Burp.Montoya.userInterface().createRawEditor().getTextAreaComponent().font)
                this.runningJob = null
            }
        } catch (e: CancellationException) {
            Logger.debug("Formatting job cancelled")
        } catch (e: Exception) {
            Logger.warning("Formatting job produced an exception: ${e.message}")
        }

    }
}
