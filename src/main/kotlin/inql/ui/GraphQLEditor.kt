package inql.ui

import burp.Burp
import inql.Config
import inql.Logger
import inql.graphql.formatting.Formatter
import inql.graphql.formatting.Style
import inql.graphql.formatting.StyleMetadata
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.util.concurrent.CancellationException
import javax.swing.*
import javax.swing.JEditorPane.HONOR_DISPLAY_PROPERTIES
import javax.swing.text.*


class GraphQLEditor(readOnly: Boolean = false, val isIntrospection: Boolean = false) : JPanel(BorderLayout()) {

    private val formatter = Formatter(false, 4, isIntrospection = isIntrospection)
    private val formattingCoroutineScope = CoroutineScope(Dispatchers.Default)
    private val watchdogCouroutingScope = CoroutineScope(Dispatchers.Default)
    private var runningJob: Job? = null
    private val timeout = Config.getInstance().getInt("editor.formatting.timeout") ?: 1000
    private val shouldWordWrap = Config.getInstance().getBoolean("editor.formatting.wordwrap")
    private val mutex = Mutex() // Prevent writing from multiple coroutines at the same time
    private val backgroundColor = if (Burp.isDarkMode()) Color(43, 43, 43) else Color.WHITE

    private var normalTextStyle = SimpleAttributeSet().also {
        val editorFont = Burp.Montoya.userInterface().currentEditorFont()
        StyleConstants.setFontFamily(it, editorFont.family)
        StyleConstants.setFontSize(it, editorFont.size)
        StyleConstants.setForeground(it, Style.STYLE_COLORS_BY_THEME[Burp.Montoya.userInterface().currentTheme()]!![Style.StyleClass.NONE])
    }

    private var styleMap = Style.STYLE_COLORS_BY_THEME[Burp.Montoya.userInterface().currentTheme()]!!.entries.associate {
        it.key to SimpleAttributeSet().also { style -> StyleConstants.setForeground(style, it.value) }
    }

    val textPane = JTextPane().also {
        it.isEditable = !readOnly
        it.putClientProperty(HONOR_DISPLAY_PROPERTIES, true)
        it.editorKit = WrapEditorKit()
        it.background = backgroundColor
    }

    private val textPaneContainer = JPanel(BorderLayout()).also {
        it.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
        it.add(textPane, BorderLayout.CENTER)
    }

    private val scrollPane = JScrollPane(textPaneContainer).also {
        it.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        it.verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        it.verticalScrollBar.unitIncrement = 16
    }

    private fun updateComponentSize() {
        try {
            if (shouldWordWrap == true) {
                this.textPaneContainer.preferredSize = Dimension(this.scrollPane.preferredSize.width, textPane.preferredSize.height)
            }
            scrollPane.horizontalScrollBar?.unitIncrement = 16
        } catch (e: Exception) {
            Logger.error("Exception caught while resizing JTextPane")
        }

    }

    init {
        this.add(scrollPane, BorderLayout.CENTER)
    }

    fun getQuery(): String {
        val doc = this.textPane.styledDocument
        val content = doc.getText(0, doc.length)
        return content
    }

    fun clear() {
        this.textPane.styledDocument.remove(0, this.textPane.styledDocument.length)
    }

    fun setPlaintext(content: String) {
        SwingUtilities.invokeLater {
            this.clear()
            try {
                this.textPane.styledDocument.insertString(0, content, normalTextStyle)
            } catch (e: OutOfMemoryError) {
                this.clear()
                this.textPane.styledDocument.insertString(0,"Request too large to display. Out of memory: ${e.message}", normalTextStyle)
            }
            this.updateComponentSize()
            this.scrollPane.verticalScrollBar.value = 0
            this.textPane.caretPosition = 0
        }
    }

    private fun setFormatted(content: String, styleMetadata: List<StyleMetadata>) {
        SwingUtilities.invokeLater {
            this.clear()
            try {
                this.textPane.styledDocument.insertString(0, content, normalTextStyle)
                for (styledToken in styleMetadata) {
                    this.textPane.styledDocument.setCharacterAttributes(styledToken.start, styledToken.length, styleMap[styledToken.styleClass], false)
                }
            } catch (e: OutOfMemoryError) {
                this.clear()
                this.textPane.styledDocument.insertString(0,"Request too large to display. Out of memory: ${e.message}", normalTextStyle)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Logger.warning("Exception caught while setting query")
            }
            this.updateComponentSize()
            this.scrollPane.verticalScrollBar.value = 0
            this.textPane.caretPosition = 0
        }
    }

    fun setQuery(s: String) {
        val runningJob = this.runningJob
        if (runningJob != null) {
            this.runningJob = null
            runningJob.cancel()
        }
        val job = this.formattingCoroutineScope.launch { this@GraphQLEditor.format(s) }
        this.runningJob = job
        this.watchdogCouroutingScope.launch { this@GraphQLEditor.timeout(job, this@GraphQLEditor.timeout) }
    }

    private suspend fun timeout(job: Job, timeout: Int) {
        delay(timeout.toLong())
        if (job.isActive) {
            job.cancel()
            mutex.withLock {
                this.setPlaintext("Formatting job cancelled due to exceeding timeout: ${timeout}ms")
            }
        }
    }

    private suspend fun format(s: String) {
        try {
            val (text, highlightInfo) = formatter.format(s)
            mutex.withLock {
                this.setFormatted(text, highlightInfo)
                this.runningJob = null
            }
        } catch (e: CancellationException) {
            Logger.debug("Formatting job cancelled")
        } catch (e: Exception) {
            Logger.warning("Formatting job produced an exception: ${e.message}")
        }
    }
}
