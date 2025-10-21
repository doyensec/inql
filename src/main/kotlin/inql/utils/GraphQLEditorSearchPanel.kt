package inql.utils

import java.awt.*
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.BadLocationException
import javax.swing.text.DefaultHighlighter

class GraphQLEditorSearchPanel(private val textPane: JTextPane) : JPanel(BorderLayout()) {
    /**
     * UI
     */

    private val searchField = JTextField().apply {
        // Set reasonable initial size
        preferredSize = Dimension(300, preferredSize.height)
        // Allow shrinking
        minimumSize = Dimension(100, preferredSize.height)
        // Allow expanding
        maximumSize = Dimension(Int.MAX_VALUE, preferredSize.height)

        putClientProperty("JTextField.placeholderText", "Search...")
    }

    private val nextButton = JButton("ᐳ").also { it.toolTipText = "Find next occurrence" }
    private val prevButton = JButton("ᐸ").also { it.toolTipText = "Find previous occurrence" }
    private val statusLabel = JLabel("0 matches")

    private val caseCheckBox = JCheckBox("Match Case").apply {
        toolTipText = "Enable case-sensitive search"
        isSelected = false  // Default to case-insensitive
    }

    private val searchPanel = JPanel(GridBagLayout()).apply {
        border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        isVisible = true

        val gbc = GridBagConstraints().apply {
            insets = Insets(0, 4, 0, 4)  // Horizontal spacing between components
            anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.NONE
            weightx = 0.0
        }

        gbc.gridx = 0
        add(prevButton, gbc)
        gbc.gridx = 1
        add(nextButton, gbc)
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0  // This makes the field take available space
        add(searchField, gbc)
        gbc.gridx = 3
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        add(statusLabel, gbc)
        gbc.gridx = 4
        add(caseCheckBox, gbc)

        // Set button margins
        listOf(prevButton, nextButton).forEach {
            it.margin = Insets(2, 5, 2, 5)
        }
    }

    /**
     * Search logic
     */

    private var matches = emptyList<Pair<Int, Int>>()
    private var currentMatchIndex = -1
    private val highlightPainter = DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW)

    private fun updateMatches() {
        val searchText = searchField.text

        textPane.highlighter.removeAllHighlights()

        if (searchText.isEmpty()) {
            matches = emptyList()
            currentMatchIndex = -1
            statusLabel.text = "0 matches"
            return
        }

        val content = textPane.text
        matches = buildList {
            if (caseCheckBox.isSelected) {
                // Case-sensitive search (original behavior)
                var index = 0
                while (index <= content.length) {
                    val found = content.indexOf(searchText, index)
                    if (found == -1) break
                    add(found to (found + searchText.length))
                    index = found + 1
                }
            } else {
                // Case-insensitive search
                val contentLower = content.lowercase()
                val searchTextLower = searchText.lowercase()
                var index = 0

                while (index <= contentLower.length) {
                    val found = contentLower.indexOf(searchTextLower, index)
                    if (found == -1) break
                    add(found to (found + searchText.length))
                    index = found + 1
                }
            }
        }

        matches.forEach { (start, end) ->
            textPane.highlighter.addHighlight(start, end, highlightPainter)
        }

        currentMatchIndex = if (matches.isNotEmpty()) 0 else -1
        updateStatus()
        selectCurrentMatch()
    }

    private fun selectCurrentMatch() {
        if (currentMatchIndex in matches.indices) {
            val (start, end) = matches[currentMatchIndex]
            textPane.selectionStart = start
            textPane.selectionEnd = end

            try {
                val startRect = textPane.modelToView2D(start)?.bounds
                val endRect = textPane.modelToView2D(end)?.bounds

                if (startRect != null && endRect != null) {
                    val viewRect = startRect.union(endRect)
                    textPane.scrollRectToVisible(viewRect)
                }
            } catch (e: BadLocationException) {
                // Handle invalid positions
                statusLabel.text = "Invalid position"
            }
        }
    }

    private fun updateStatus() {
        statusLabel.text = when {
            matches.isEmpty() -> "0 matches"
            else -> "${currentMatchIndex + 1}/${matches.size} matches"
        }
    }


    private val searchTimer = Timer(300) { updateMatches() }.apply { isRepeats = false }
    private var isUpdating = false

    init {
        searchField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = searchTimer.restart()
            override fun removeUpdate(e: DocumentEvent) = searchTimer.restart()
            override fun changedUpdate(e: DocumentEvent) {}
        })

        nextButton.addActionListener {
            if (matches.isNotEmpty()) {
                currentMatchIndex = (currentMatchIndex + 1) % matches.size
                selectCurrentMatch()
                updateStatus()
            }
        }

        prevButton.addActionListener {
            if (matches.isNotEmpty()) {
                currentMatchIndex = if (--currentMatchIndex < 0) matches.lastIndex else currentMatchIndex
                selectCurrentMatch()
                updateStatus()
            }
        }

        caseCheckBox.addActionListener {
            updateMatches()
        }

        // when switching between queries
        textPane.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) { handleTextChange() }
            override fun removeUpdate(e: DocumentEvent) { }
            override fun changedUpdate(e: DocumentEvent) { }

            private fun handleTextChange() {
                if (isUpdating) return

                isUpdating = true
                SwingUtilities.invokeLater {
                    try {
                        if (textPane.document.length == textPane.text.length) {
                            updateMatches()
                        }
                    } finally {
                        isUpdating = false
                    }
                }
            }
        })

        this.add(searchPanel, BorderLayout.CENTER)
    }
}