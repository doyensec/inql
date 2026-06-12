package inql.scanner.scanresults

import burp.Burp
import inql.Logger
import inql.graphql.scanners.CycleDetectionExport
import inql.graphql.scanners.CycleResult
import inql.scanner.ScanResult
import inql.ui.BorderPanel
import inql.ui.FlowPanel
import inql.ui.MenuAction
import inql.ui.SendFromInqlHandler
import inql.utils.QueryToRequestConverter
import java.io.File
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.Point
import java.awt.Rectangle
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.JPopupMenu
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.JTableHeader
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardOpenOption

class CycleDetectionPanel(private val view: ScanResultsView) : BorderPanel(8) {
    private val searchField = JTextField(24)
    private val exportButton = JButton("Export All as Text")
    private val headerBar = FlowPanel(FlowLayout.LEFT, 8).apply {
        // Space between search/export row and the table (BorderLayout has no inter-region gap).
        border = BorderFactory.createEmptyBorder(0, 0, 4, 0)
        add(JLabel("Search:"))
        add(searchField)
        add(exportButton)
    }

    private val tableModel = CycleTableModel()
    private val table = JTable(tableModel).apply {
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        autoCreateRowSorter = false
        fillsViewportHeight = false
        rowHeight = 24
        setShowGrid(false)
        autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        columnModel.getColumn(0).apply {
            minWidth = 120
            preferredWidth = 400
        }
        columnModel.getColumn(1).apply {
            minWidth = 48
            preferredWidth = 60
        }
        columnModel.getColumn(2).apply {
            minWidth = 120
            preferredWidth = 400
        }
    }

    private val prevButton = JButton("Prev")
    private val nextButton = JButton("Next")
    private val pageLabel = JLabel()
    private val pageSizeCombo = JComboBox(arrayOf(25, 50, 100)).apply {
        selectedItem = 50
    }

    private val paginationBar = FlowPanel(FlowLayout.LEFT, 8).apply {
        border = BorderFactory.createEmptyBorder(4, 0, 0, 0)
        add(prevButton)
        add(nextButton)
        add(JLabel("Page"))
        add(pageLabel)
        add(JLabel("Rows per page:"))
        add(pageSizeCombo)
    }

    private val loadingLabel = JLabel("Scanning schema for cycles…", JLabel.CENTER).apply {
        border = BorderFactory.createEmptyBorder(24, 8, 24, 8)
    }

    private val centerCard = JPanel(BorderLayout()).apply {
        add(JScrollPane(table), BorderLayout.CENTER)
    }

    private var scanResult: ScanResult? = null
    private var allCycles: List<CycleResult> = emptyList()

    private val rightClickHandler = object : SendFromInqlHandler(view.scannerTab.inql, false, false) {
        override fun getRequest() = buildRequestForSelectedCycle()
        override fun getText(): String = view.getPayloadText()

        override fun appendBottomContextMenuItems(popup: JPopupMenu) {
            val row = table.selectedRow
            val canCopy = row >= 0 && tableModel.cycleAt(row) != null
            val action = MenuAction("Copy Cycle Path", null) {
                copySelectedPathPreviewToClipboard()
            }
            action.isEnabled = canCopy
            popup.addSeparator()
            popup.add(action)
        }
    }

    init {
        border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
        add(BorderLayout.NORTH, headerBar)
        add(BorderLayout.SOUTH, paginationBar)
        add(BorderLayout.CENTER, centerCard)

        tableModel.pageSize = pageSizeCombo.selectedItem as Int

        exportButton.addActionListener { exportAllToFile() }
        prevButton.addActionListener {
            tableModel.prevPage()
            updatePaginationUi()
        }
        nextButton.addActionListener {
            tableModel.nextPage()
            updatePaginationUi()
        }
        pageSizeCombo.addActionListener {
            tableModel.pageSize = pageSizeCombo.selectedItem as Int
            tableModel.page = 0
            tableModel.refreshPage()
            updatePaginationUi()
        }

        searchField.document.addDocumentListener(object : DocumentListener {
            private fun apply() {
                tableModel.filter = searchField.text
                updatePaginationUi()
            }
            override fun insertUpdate(e: DocumentEvent) = apply()
            override fun removeUpdate(e: DocumentEvent) = apply()
            override fun changedUpdate(e: DocumentEvent) = apply()
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

        // Sort on header press, but not on column resize drags (edges of header cells)
        table.tableHeader.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                if (!SwingUtilities.isLeftMouseButton(e)) return
                val col = headerColumnIndexForSort(table.tableHeader, e.point)
                if (col >= 0) {
                    tableModel.toggleSort(col)
                    updatePaginationUi()
                    table.tableHeader.repaint()
                }
            }
        })
        table.tableHeader.reorderingAllowed = false

        rightClickHandler.addRightClickHandler(table)
        rightClickHandler.addKeyboardShortcutHandler(table)

        updatePaginationUi()
    }

    /**
     * Returns the column to sort, or -1 if [p] is in a resize zone (or outside header cells).
     * Mirrors the idea of BasicTableHeaderUI: ignore clicks near column boundaries.
     */
    private fun headerColumnIndexForSort(header: JTableHeader, p: Point): Int {
        val col = header.columnAtPoint(p)
        if (col < 0) return -1
        val r = header.getHeaderRect(col)
        val margin = 5
        val innerWidth = (r.width - 2 * margin).coerceAtLeast(1)
        val inner = Rectangle(r.x + margin, r.y, innerWidth, r.height)
        return if (inner.contains(p)) col else -1
    }

    private fun copySelectedPathPreviewToClipboard() {
        val row = table.selectedRow
        if (row < 0) return
        val cycle = tableModel.cycleAt(row) ?: return
        val text = cycle.pathPreview()
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }

    private fun buildRequestForSelectedCycle(): burp.api.montoya.http.message.requests.HttpRequest? {
        val sr = scanResult ?: return null
        val row = table.selectedRow
        if (row < 0) return null
        val cycle = tableModel.cycleAt(row) ?: return null
        val json = QueryToRequestConverter(sr).buildCyclePocJson(cycle)
        return view.requestTemplateWithBody(view.effectiveRequestTemplate(), json)
    }

    /** Full cycle report text (same as Export All), for Save to file from the scanner context menu. */
    fun getExportText(): String = CycleDetectionExport.formatAll(allCycles)

    private fun exportAllToFile() {
        val text = getExportText()
        val chooser = JFileChooser().apply {
            dialogType = JFileChooser.SAVE_DIALOG
            dialogTitle = "Export cycles"
            selectedFile = File("inql-cycles-export.txt")
        }
        val parent = Burp.Montoya.userInterface().swingUtils().suiteFrame()
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return

        var file = chooser.selectedFile
        if (file == null || file.name.isBlank()) {
            Logger.warning("Export cycles: no file chosen")
            return
        }
        if (!file.isAbsolute) {
            file = File(chooser.currentDirectory, file.name)
        }
        try {
            file.parentFile?.mkdirs()
            Files.writeString(
                file.toPath(),
                text,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            )
        } catch (e: Exception) {
            Logger.error("Export cycles failed: ${e.message}")
        }
    }

    fun release() {
        scanResult = null
        allCycles = emptyList()
        tableModel.setAllCycles(emptyList())
    }

    fun showLoading() {
        scanResult = null
        allCycles = emptyList()
        loadingLabel.isVisible = true
        centerCard.removeAll()
        centerCard.add(loadingLabel, BorderLayout.CENTER)
        centerCard.revalidate()
        centerCard.repaint()
        headerBar.isEnabled = false
        paginationBar.isEnabled = false
    }

    fun showResults(sr: ScanResult, cycles: List<CycleResult>) {
        scanResult = sr
        allCycles = cycles
        searchField.text = ""
        tableModel.setAllCycles(cycles)
        headerBar.isEnabled = true
        paginationBar.isEnabled = true
        centerCard.removeAll()
        centerCard.add(JScrollPane(table), BorderLayout.CENTER)
        centerCard.revalidate()
        centerCard.repaint()
        updatePaginationUi()
    }

    private fun updatePaginationUi() {
        val tm = tableModel
        pageLabel.text = "${tm.page + 1} / ${maxOf(1, tm.pageCount)}"
        prevButton.isEnabled = tm.page > 0 && tm.hasFilteredData()
        nextButton.isEnabled = tm.page < tm.pageCount - 1 && tm.hasFilteredData()
        tm.fireTableDataChanged()
    }

    private inner class CycleTableModel : AbstractTableModel() {
        private val columnBases = arrayOf("Entrypoint", "Depth", "Path Preview")

        private var sortColumn: Int = 0
        private var sortAscending: Boolean = true

        var filter: String = ""
            set(value) {
                field = value
                applyFilter()
            }

        var all: List<CycleResult> = emptyList()
        var filtered: List<CycleResult> = emptyList()
        /** Filtered rows, then sorted (full list for current search). */
        private var sortedRows: List<CycleResult> = emptyList()
        var page: Int = 0
        var pageSize: Int = 50

        val pageCount: Int
            get() = if (sortedRows.isEmpty()) 1 else (sortedRows.size + pageSize - 1) / pageSize

        fun setAllCycles(cycles: List<CycleResult>) {
            all = cycles
            applyFilter()
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
            // Data-only update — fireTableStructureChanged() resets column sizes
            refreshPage()
        }

        private fun applyFilter() {
            val q = filter.trim().lowercase()
            filtered = if (q.isEmpty()) {
                all
            } else {
                all.filter { c ->
                    c.entrypoint.lowercase().contains(q) ||
                        c.pathPreview().lowercase().contains(q)
                }
            }
            page = 0
            refreshSortedRows()
            refreshPage()
        }

        private fun refreshSortedRows() {
            val pathKey: (CycleResult) -> String = { it.pathFieldNames.joinToString("/") }
            val base: Comparator<CycleResult> = when (sortColumn) {
                0 -> compareBy<CycleResult, String>(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
                    .thenBy { it.depth }
                    .thenBy(String.CASE_INSENSITIVE_ORDER, pathKey)
                1 -> compareBy<CycleResult> { it.depth }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
                    .thenBy(String.CASE_INSENSITIVE_ORDER, pathKey)
                2 -> compareBy<CycleResult, String>(String.CASE_INSENSITIVE_ORDER, pathKey)
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
                else -> compareBy<CycleResult, String>(String.CASE_INSENSITIVE_ORDER) { it.entrypoint }
            }
            sortedRows = filtered.sortedWith(if (sortAscending) base else base.reversed())
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

        fun hasFilteredData(): Boolean = sortedRows.isNotEmpty()

        fun cycleAt(displayRow: Int): CycleResult? {
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
            val c = cycleAt(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> c.entrypoint
                1 -> c.depth
                2 -> c.pathPreview()
                else -> null
            }
        }

        override fun isCellEditable(row: Int, column: Int): Boolean = false
    }
}
