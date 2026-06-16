package inql.scanner.scanresults

import burp.Burp
import inql.graphql.GQLSchema
import inql.graphql.scanners.PathEnumerationExport
import inql.graphql.scanners.PathEnumerationScanner
import inql.graphql.scanners.PathResult
import inql.graphql.scanners.PathSearchTarget
import inql.scanner.ScanResult
import inql.schema.corrections.SchemaTypeCatalog
import inql.ui.BorderPanel
import inql.ui.FlowPanel
import inql.ui.MenuAction
import inql.ui.SendFromInqlHandler
import inql.utils.QueryToRequestConverter
import inql.Logger
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Point
import java.awt.Rectangle
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SpinnerNumberModel
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.JTableHeader
import javax.swing.JComboBox

private data class TargetSuggestion(
    val label: String,
    val target: PathSearchTarget,
) {
    override fun toString(): String = label
}

class PathEnumerationPanel(private val view: ScanResultsView) : BorderPanel(8) {
    companion object {
        private const val MAX_SUGGESTIONS = 150
    }

    private val targetField = JTextField(28)
    private var selectedTarget: TargetSuggestion? = null
    private var updatingTargetField = false

    private val suggestionListModel = DefaultListModel<TargetSuggestion>()
    private val suggestionList = JList(suggestionListModel).apply {
        visibleRowCount = 8
        selectionMode = ListSelectionModel.SINGLE_SELECTION
    }
    private val suggestionsPanel = BorderPanel(0).apply {
        border = BorderFactory.createEmptyBorder(2, 0, 4, 0)
        add(JScrollPane(suggestionList).apply {
            preferredSize = Dimension(0, 140)
        }, BorderLayout.CENTER)
        isVisible = false
    }

    private val depthSpinner = JSpinner(SpinnerNumberModel(5, 1, 50, 1))
    private val includeQueryCheck = JCheckBox("Include Queries", true)
    private val includeMutationCheck = JCheckBox("Include Mutations", true)
    private val includeSubscriptionCheck = JCheckBox("Include Subscriptions", true)
    private val searchButton = JButton("Search")

    private val controlBar = FlowPanel(FlowLayout.LEFT, 8).apply {
        border = BorderFactory.createEmptyBorder(0, 0, 4, 0)
        add(JLabel("Target:"))
        add(targetField)
        add(JLabel("Max depth:"))
        add(depthSpinner)
        add(includeQueryCheck)
        add(includeMutationCheck)
        add(includeSubscriptionCheck)
        add(searchButton)
    }

    private val northPanel = JPanel(BorderLayout()).apply {
        add(controlBar, BorderLayout.NORTH)
        add(suggestionsPanel, BorderLayout.SOUTH)
    }

    private val tableModel = PathTableModel()
    private val table = JTable(tableModel).apply {
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        autoCreateRowSorter = false
        fillsViewportHeight = false
        rowHeight = 24
        setShowGrid(false)
        autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        columnModel.getColumn(0).apply {
            minWidth = 48
            preferredWidth = 60
        }
        columnModel.getColumn(1).apply {
            minWidth = 120
            preferredWidth = 120
        }
        columnModel.getColumn(2).apply {
            minWidth = 200
            preferredWidth = 500
        }
    }

    private val prevButton = JButton("Prev")
    private val nextButton = JButton("Next")
    private val pageLabel = JLabel()
    private val pageSizeCombo = JComboBox(arrayOf(25, 50, 100)).apply {
        selectedItem = 50
    }
    private val exportButton = JButton("Export CSV")
    private val statusLabel = JLabel(" ")

    private val footerBar = FlowPanel(FlowLayout.LEFT, 8).apply {
        border = BorderFactory.createEmptyBorder(4, 0, 0, 0)
        add(exportButton)
        add(prevButton)
        add(nextButton)
        add(JLabel("Page"))
        add(pageLabel)
        add(JLabel("Rows per page:"))
        add(pageSizeCombo)
        add(statusLabel)
    }

    private val loadingLabel = JLabel("Searching schema for paths…", JLabel.CENTER).apply {
        border = BorderFactory.createEmptyBorder(24, 8, 24, 8)
    }

    private val centerCard = JPanel(BorderLayout()).apply {
        isFocusable = true
        add(JScrollPane(table), BorderLayout.CENTER)
    }

    private var scanResult: ScanResult? = null
    private var gqlSchema: GQLSchema? = null
    private var activeEntry: PathEnumerationEntry? = null
    private var allSuggestions: List<TargetSuggestion> = emptyList()
    private var searchRunning = false

    private val rightClickHandler = object : SendFromInqlHandler(view.scannerTab.inql, false, false) {
        override fun getRequest() = buildRequestForSelectedPath()
        override fun getText(): String = view.getPayloadText()

        override fun appendBottomContextMenuItems(popup: JPopupMenu) {
            val row = table.selectedRow
            val canCopy = row >= 0 && tableModel.pathAt(row) != null
            val action = MenuAction("Copy Path to Clipboard", null) {
                copySelectedPathToClipboard()
            }
            action.isEnabled = canCopy
            popup.addSeparator()
            popup.add(action)
        }
    }

    init {
        border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
        add(BorderLayout.NORTH, northPanel)
        add(BorderLayout.SOUTH, footerBar)
        add(BorderLayout.CENTER, centerCard)

        tableModel.pageSize = pageSizeCombo.selectedItem as Int

        searchButton.addActionListener { runSearch() }
        exportButton.addActionListener { exportAllToCsv() }
        prevButton.addActionListener {
            tableModel.prevPage()
            updatePaginationUi()
            persistState()
        }
        nextButton.addActionListener {
            tableModel.nextPage()
            updatePaginationUi()
            persistState()
        }
        pageSizeCombo.addActionListener {
            tableModel.pageSize = pageSizeCombo.selectedItem as Int
            tableModel.page = 0
            tableModel.refreshPage()
            updatePaginationUi()
            persistState()
        }

        targetField.document.addDocumentListener(object : DocumentListener {
            private fun apply() {
                if (updatingTargetField) return
                val text = targetField.text.trim()
                if (selectedTarget != null && !selectedTarget!!.label.equals(text, ignoreCase = true)) {
                    selectedTarget = null
                }
                scheduleSuggestionRefresh()
            }
            override fun insertUpdate(e: DocumentEvent) = apply()
            override fun removeUpdate(e: DocumentEvent) = apply()
            override fun changedUpdate(e: DocumentEvent) = apply()
        })

        targetField.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                when (e.keyCode) {
                    KeyEvent.VK_DOWN -> {
                        if (suggestionsPanel.isVisible && suggestionListModel.size > 0) {
                            suggestionList.requestFocusInWindow()
                            if (suggestionList.selectedIndex < 0) {
                                suggestionList.selectedIndex = 0
                            }
                            e.consume()
                        }
                    }
                    KeyEvent.VK_ENTER -> runSearch()
                    KeyEvent.VK_ESCAPE -> hideSuggestions()
                }
            }
        })

        targetField.addFocusListener(object : FocusAdapter() {
            override fun focusGained(e: FocusEvent) {
                if (targetField.text.trim().isEmpty()) {
                    scheduleSuggestionRefresh()
                }
            }

            override fun focusLost(e: FocusEvent) {
                SwingUtilities.invokeLater {
                    val opposite = e.oppositeComponent
                    if (opposite != suggestionList && !SwingUtilities.isDescendingFrom(opposite, suggestionsPanel)) {
                        hideSuggestions()
                    }
                }
            }
        })

        suggestionList.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                val idx = suggestionList.locationToIndex(e.point)
                if (idx >= 0) {
                    acceptSuggestion(suggestionListModel.getElementAt(idx))
                }
            }
        })

        suggestionList.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                when (e.keyCode) {
                    KeyEvent.VK_ENTER -> {
                        val idx = suggestionList.selectedIndex
                        if (idx >= 0) {
                            acceptSuggestion(suggestionListModel.getElementAt(idx))
                            e.consume()
                        }
                    }
                    KeyEvent.VK_ESCAPE -> {
                        hideSuggestions()
                        targetField.requestFocusInWindow()
                        e.consume()
                    }
                }
            }
        })

        table.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    val row = table.rowAtPoint(e.point)
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row)
                    }
                }
            }
        })

        table.tableHeader.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                if (!SwingUtilities.isLeftMouseButton(e)) return
                val col = headerColumnIndexForSort(table.tableHeader, e.point)
                if (col >= 0) {
                    tableModel.toggleSort(col)
                    updatePaginationUi()
                    table.tableHeader.repaint()
                    persistState()
                }
            }
        })
        table.tableHeader.reorderingAllowed = false

        rightClickHandler.addRightClickHandler(table)
        rightClickHandler.addKeyboardShortcutHandler(table)

        updatePaginationUi()
    }

    private fun scheduleSuggestionRefresh() {
        SwingUtilities.invokeLater { refreshSuggestions() }
    }

    private fun headerColumnIndexForSort(header: JTableHeader, p: Point): Int {
        val col = header.columnAtPoint(p)
        if (col < 0) return -1
        val r = header.getHeaderRect(col)
        val margin = 5
        val innerWidth = (r.width - 2 * margin).coerceAtLeast(1)
        val inner = Rectangle(r.x + margin, r.y, innerWidth, r.height)
        return if (inner.contains(p)) col else -1
    }

    private fun hideSuggestions() {
        if (!suggestionsPanel.isVisible) return
        suggestionsPanel.isVisible = false
        northPanel.revalidate()
        northPanel.repaint()
    }

    private fun acceptSuggestion(suggestion: TargetSuggestion) {
        updatingTargetField = true
        try {
            selectedTarget = suggestion
            targetField.text = suggestion.label
            targetField.caretPosition = suggestion.label.length
        } finally {
            updatingTargetField = false
        }
        hideSuggestions()
        targetField.requestFocusInWindow()
        persistState()
    }

    private fun refreshSuggestions() {
        val q = targetField.text.trim()
        val filtered = if (q.isEmpty()) {
            allSuggestions.take(MAX_SUGGESTIONS)
        } else {
            allSuggestions
                .asSequence()
                .filter { it.label.contains(q, ignoreCase = true) }
                .take(MAX_SUGGESTIONS)
                .toList()
        }

        suggestionListModel.clear()
        filtered.forEach { suggestionListModel.addElement(it) }

        if (filtered.isEmpty()) {
            hideSuggestions()
            return
        }

        suggestionList.selectedIndex = 0
        if (!suggestionsPanel.isVisible) {
            suggestionsPanel.isVisible = true
            northPanel.revalidate()
            northPanel.repaint()
        }
    }

    fun persistState() {
        val entry = activeEntry ?: return
        entry.state = captureState()
    }

    fun load(entry: PathEnumerationEntry) {
        if (activeEntry === entry) return
        persistState()
        activeEntry = entry
        scanResult = entry.scanResult
        gqlSchema = entry.gqlSchema
        allSuggestions = buildSuggestions(entry.scanResult)
        applyState(entry.state)
    }

    fun release() {
        persistState()
        activeEntry = null
        scanResult = null
        gqlSchema = null
        allSuggestions = emptyList()
        selectedTarget = null
        tableModel.setPaths(emptyList())
    }

    private fun captureState(): PathEnumerationState {
        return PathEnumerationState(
            targetText = targetField.text,
            selectedTargetLabel = selectedTarget?.label,
            maxDepth = depthSpinner.value as Int,
            includeQuery = includeQueryCheck.isSelected,
            includeMutation = includeMutationCheck.isSelected,
            includeSubscription = includeSubscriptionCheck.isSelected,
            paths = tableModel.all,
            statusText = statusLabel.text.trim(),
            tablePage = tableModel.page,
            tablePageSize = tableModel.pageSize,
            sortColumn = tableModel.sortColumn,
            sortAscending = tableModel.sortAscending,
        )
    }

    private fun applyState(state: PathEnumerationState) {
        depthSpinner.value = state.maxDepth
        includeQueryCheck.isSelected = state.includeQuery
        includeMutationCheck.isSelected = state.includeMutation
        includeSubscriptionCheck.isSelected = state.includeSubscription
        pageSizeCombo.selectedItem = state.tablePageSize

        updatingTargetField = true
        try {
            targetField.text = state.targetText
            selectedTarget = state.selectedTargetLabel?.let { label ->
                allSuggestions.find { it.label.equals(label, ignoreCase = true) }
            }
        } finally {
            updatingTargetField = false
        }

        hideSuggestions()
        tableModel.restore(
            paths = state.paths,
            page = state.tablePage,
            pageSize = state.tablePageSize,
            sortColumn = state.sortColumn,
            sortAscending = state.sortAscending,
        )
        statusLabel.text = state.statusText.ifEmpty {
            "Pick a type or field from the suggestions, then click Search."
        }
        centerCard.removeAll()
        centerCard.add(JScrollPane(table), BorderLayout.CENTER)
        centerCard.revalidate()
        centerCard.repaint()
        controlBar.isEnabled = true
        footerBar.isEnabled = true
        updatePaginationUi()
    }

    private fun blurTargetField() {
        hideSuggestions()
        SwingUtilities.invokeLater {
            when {
                table.isShowing && table.rowCount > 0 -> table.requestFocusInWindow()
                centerCard.isShowing -> centerCard.requestFocusInWindow()
                else -> searchButton.requestFocusInWindow()
            }
        }
    }

    private fun buildSuggestions(scanResult: ScanResult): List<TargetSuggestion> {
        val catalog = SchemaTypeCatalog.fromScanResult(scanResult)
        val operationRoots = catalog.operationRootTypes.toSet()
        val suggestions = mutableListOf<TargetSuggestion>()

        for (typeName in catalog.outputTypes.sorted()) {
            suggestions.add(
                TargetSuggestion(
                    label = typeName,
                    target = PathSearchTarget.TypeTarget(typeName),
                ),
            )
        }

        val fieldsByName = linkedMapOf<String, MutableSet<String>>()
        for ((typeName, fields) in catalog.outputTypeFields) {
            if (typeName in operationRoots) continue
            for (fieldName in fields) {
                fieldsByName.getOrPut(fieldName) { mutableSetOf() }.add(typeName)
            }
        }

        for ((fieldName, typeNames) in fieldsByName.toSortedMap()) {
            val nonRootTypes = typeNames.filter { it !in operationRoots }.toSet()
            if (nonRootTypes.isEmpty()) continue
            val label = if (nonRootTypes.size == 1) {
                "$fieldName (${nonRootTypes.first()})"
            } else {
                fieldName
            }
            suggestions.add(
                TargetSuggestion(
                    label = label,
                    target = PathSearchTarget.FieldTarget(fieldName, nonRootTypes),
                ),
            )
        }

        return suggestions.sortedBy { it.label.lowercase() }
    }

    private fun resolveTarget(): PathSearchTarget? {
        val text = targetField.text.trim()
        if (text.isEmpty()) return null

        selectedTarget?.takeIf { it.label.equals(text, ignoreCase = true) }?.target?.let { return it }
        return allSuggestions.find { it.label.equals(text, ignoreCase = true) }?.target
    }

    private fun runSearch() {
        hideSuggestions()
        if (searchRunning) return
        val sr = scanResult ?: return
        val schema = gqlSchema ?: return
        val target = resolveTarget()
        if (target == null) {
            statusLabel.text = "Select a valid type or field from the suggestions."
            blurTargetField()
            return
        }

        val maxDepth = depthSpinner.value as Int
        val includeQuery = includeQueryCheck.isSelected
        val includeMutation = includeMutationCheck.isSelected
        val includeSubscription = includeSubscriptionCheck.isSelected

        if (!includeQuery && !includeMutation && !includeSubscription) {
            statusLabel.text = "Enable at least one entry point (Query, Mutation, or Subscription)."
            blurTargetField()
            return
        }

        blurTargetField()
        searchRunning = true
        searchButton.isEnabled = false
        statusLabel.text = "Searching…"
        centerCard.removeAll()
        centerCard.add(loadingLabel, BorderLayout.CENTER)
        centerCard.revalidate()
        centerCard.repaint()

        CoroutineScope(Dispatchers.Default).launch {
            val paths = try {
                PathEnumerationScanner(
                    schema = schema,
                    maxDepth = maxDepth,
                    includeQuery = includeQuery,
                    includeMutation = includeMutation,
                    includeSubscription = includeSubscription,
                ).enumerate(target)
            } catch (_: Exception) {
                emptyList()
            }

            withContext(Dispatchers.Swing) {
                searchRunning = false
                searchButton.isEnabled = true
                tableModel.setPaths(paths)
                centerCard.removeAll()
                centerCard.add(JScrollPane(table), BorderLayout.CENTER)
                centerCard.revalidate()
                centerCard.repaint()
                updatePaginationUi()
                statusLabel.text = when {
                    paths.isEmpty() -> "No paths found."
                    else -> "Found ${paths.size} path(s)."
                }
                persistState()
                blurTargetField()
            }
        }
    }

    private fun copySelectedPathToClipboard() {
        val row = table.selectedRow
        if (row < 0) return
        val path = tableModel.pathAt(row) ?: return
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(path.pathPreview()), null)
    }

    private fun buildRequestForSelectedPath(): burp.api.montoya.http.message.requests.HttpRequest? {
        val sr = scanResult ?: return null
        val row = table.selectedRow
        if (row < 0) return null
        val path = tableModel.pathAt(row) ?: return null
        val json = QueryToRequestConverter(sr).buildPathPocJson(path)
        return view.requestTemplateWithBody(view.effectiveRequestTemplate(), json)
    }

    private fun updatePaginationUi() {
        val tm = tableModel
        pageLabel.text = "${tm.page + 1} / ${maxOf(1, tm.pageCount)}"
        prevButton.isEnabled = tm.page > 0 && tm.hasData()
        nextButton.isEnabled = tm.page < tm.pageCount - 1 && tm.hasData()
        exportButton.isEnabled = tm.hasData()
        tm.fireTableDataChanged()
    }

    private fun exportAllToCsv() {
        val paths = tableModel.allSortedRows()
        if (paths.isEmpty()) {
            Logger.warning("Export paths: no results to export")
            return
        }

        val csv = PathEnumerationExport.toCsv(paths)
        val chooser = JFileChooser().apply {
            dialogType = JFileChooser.SAVE_DIALOG
            dialogTitle = "Export path enumeration results"
            selectedFile = File("inql-paths-export.csv")
        }
        val parent = Burp.Montoya.userInterface().swingUtils().suiteFrame()
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return

        var file = chooser.selectedFile
        if (file == null || file.name.isBlank()) {
            Logger.warning("Export paths: no file chosen")
            return
        }
        if (!file.isAbsolute) {
            file = File(chooser.currentDirectory, file.name)
        }
        if (!file.name.endsWith(".csv", ignoreCase = true)) {
            file = File(file.parentFile, "${file.name}.csv")
        }
        try {
            file.parentFile?.mkdirs()
            Files.writeString(
                file.toPath(),
                csv,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            )
        } catch (e: Exception) {
            Logger.error("Export paths failed: ${e.message}")
        }
    }

    private inner class PathTableModel : AbstractTableModel() {
        private val columnBases = arrayOf("Depth", "Entrypoint", "Path")

        var sortColumn: Int = 0
            private set
        var sortAscending: Boolean = true
            private set

        var all: List<PathResult> = emptyList()
        private var sortedRows: List<PathResult> = emptyList()
        var page: Int = 0
        var pageSize: Int = 50

        val pageCount: Int
            get() = if (sortedRows.isEmpty()) 1 else (sortedRows.size + pageSize - 1) / pageSize

        fun setPaths(newPaths: List<PathResult>) {
            all = newPaths
            page = 0
            refreshSortedRows()
            refreshPage()
        }

        fun restore(
            paths: List<PathResult>,
            page: Int,
            pageSize: Int,
            sortColumn: Int,
            sortAscending: Boolean,
        ) {
            all = paths
            this.page = page
            this.pageSize = pageSize
            this.sortColumn = sortColumn
            this.sortAscending = sortAscending
            refreshSortedRows()
            refreshPage()
        }

        fun toggleSort(column: Int) {
            if (column !in 0 until columnBases.size) return
            if (sortColumn == column) {
                sortAscending = !sortAscending
            } else {
                sortColumn = column
                sortAscending = true
            }
            page = 0
            refreshSortedRows()
            refreshPage()
        }

        private fun refreshSortedRows() {
            val pathKey: (PathResult) -> String = { it.pathFieldNames.joinToString("/") }
            val base: Comparator<PathResult> = when (sortColumn) {
                0 -> compareBy<PathResult> { it.depth }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
                    .thenBy(String.CASE_INSENSITIVE_ORDER, pathKey)
                1 -> compareBy<PathResult, String>(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
                    .thenBy { it.depth }
                    .thenBy(String.CASE_INSENSITIVE_ORDER, pathKey)
                2 -> compareBy<PathResult, String>(String.CASE_INSENSITIVE_ORDER) { it.pathPreview() }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
                    .thenBy { it.depth }
                else -> compareBy<PathResult> { it.depth }
            }
            sortedRows = all.sortedWith(if (sortAscending) base else base.reversed())
        }

        fun refreshPage() {
            fireTableDataChanged()
        }

        fun prevPage() {
            if (page > 0) {
                page--
                refreshPage()
            }
        }

        fun nextPage() {
            if (page < pageCount - 1) {
                page++
                refreshPage()
            }
        }

        fun hasData(): Boolean = sortedRows.isNotEmpty()

        fun allSortedRows(): List<PathResult> = sortedRows

        fun pathAt(displayRow: Int): PathResult? {
            val idx = page * pageSize + displayRow
            return sortedRows.getOrNull(idx)
        }

        override fun getRowCount(): Int {
            if (sortedRows.isEmpty()) return 0
            val start = page * pageSize
            val remaining = sortedRows.size - start
            return remaining.coerceIn(0, pageSize)
        }

        override fun getColumnCount(): Int = 3

        override fun getColumnName(column: Int): String = columnBases[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val path = pathAt(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> path.depth
                1 -> path.entrypoint
                2 -> path.pathPreview()
                else -> null
            }
        }

        override fun isCellEditable(row: Int, column: Int): Boolean = false
    }
}
