package inql.ui

import burp.Burp
import inql.Config
import inql.Logger
import inql.graphql.formatting.Formatter
import inql.graphql.formatting.Style
import inql.utils.getTextAreaComponent
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.apache.commons.text.StringEscapeUtils
import java.awt.Font
import java.util.concurrent.CancellationException
import javax.swing.JEditorPane
import javax.swing.text.StyleConstants
import javax.swing.text.html.HTMLDocument

class GraphQLEditor(readOnly: Boolean = false, val isIntrospection: Boolean = false) : JEditorPane("text/html", "") {
    companion object {
        fun stripHTML(content: String): String {
            return StringEscapeUtils.unescapeHtml4(content.replace(Regex("<([^>]+)>"), ""))
        }

        private fun getHTML(content: String = "") =
            """
                <!DOCTYPE html>
                <html>
                <head>
                </head>
                <body>
                <pre id="content">$content</pre>
                </body>
                </html>
            """.trimIndent()
    }

    private val formatter = Formatter(false, 4, asHTML = true, isIntrospection = isIntrospection)
    private val formattingCoroutineScope = CoroutineScope(Dispatchers.Default)
    private var runningJob: Job? = null
    private val timeout = Config.getInstance().getInt("editor.formatting.timeout") ?: 1000
    private val mutex = Mutex() // Prevent writing from multiple coroutines at the same time

    init {
        this.putClientProperty(HONOR_DISPLAY_PROPERTIES, true)
        this.text = getHTML()
        if (readOnly) this.isEditable = false

        val doc = this.document as HTMLDocument
        doc.styleSheet.addRule(Style.getStyleCSS())
        Burp.Montoya.userInterface().applyThemeToComponent(this)

        // Copy Burp's editor background
        val raw = Burp.Montoya.userInterface().createRawEditor().getTextAreaComponent()
        this.background = raw.background
    }

    fun setFontInHTML(f: Font) {
        this.font = f
        val doc = this.document as HTMLDocument
        val rule = doc.styleSheet.getRule("body")
        StyleConstants.setFontFamily(rule, f.family)
        StyleConstants.setFontSize(rule, f.size)
    }

    fun getQuery(): String {
        val doc = this.document as HTMLDocument
        val pre = doc.getElement("content")
        val content = doc.getText(pre.startOffset, pre.endOffset - pre.startOffset)
        return stripHTML(content)
    }

    private fun setHTML(content: String) {
        try {
            this.text = getHTML(content)
        } catch (e: OutOfMemoryError) {
            this.text = getHTML("Request too large to display. Out of memory: ${e.message}")
        }
        this.caretPosition = 0
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
                this.setHTML(s)
            }
            mutex.unlock()
        }
    }

    suspend fun format(s: String) {
        try {
            val text = formatter.format(s)
            mutex.withLock {
                this.setHTML(text)
                this.runningJob = null
            }
        } catch (e: CancellationException) {
            Logger.debug("Formatting job cancelled")
        } catch (e: Exception) {
            Logger.warning("Formatting job produced an exception: ${e.message}")
        }

    }
}
