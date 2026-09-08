package inql.attackvector

import burp.Burp
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import javax.swing.BorderFactory
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

class ScanResultsTable(
    private val onResultSelected: (TestResult?) -> Unit,
) : AbstractTableModel() {

    private val results = mutableListOf<TestResult>()
    private val columns = listOf("Test", "Status")
    private var suppressSelectionEvents = false

    val table = JTable(this).apply {
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        autoCreateRowSorter = false
        fillsViewportHeight = false
        setShowGrid(false)
        intercellSpacing = Dimension(0, 1)
        rowHeight = ROW_HEIGHT
        autoResizeMode = JTable.AUTO_RESIZE_OFF
        tableHeader.reorderingAllowed = false
        tableHeader.defaultRenderer = HeaderRenderer()

        columnModel.apply {
            getColumn(0).cellRenderer = NameCellRenderer()
            getColumn(1).cellRenderer = StatusBadgeRenderer()
        }

        selectionModel.addListSelectionListener { e ->
            if (e.valueIsAdjusting || suppressSelectionEvents) return@addListSelectionListener
            if (selectionModel.isSelectionEmpty) {
                onResultSelected(null)
                return@addListSelectionListener
            }
            val viewRow = selectedRow
            if (viewRow < 0) return@addListSelectionListener
            val modelRow = convertRowIndexToModel(viewRow)
            if (modelRow in results.indices) {
                onResultSelected(results[modelRow])
            }
        }

        addComponentListener(object : ComponentAdapter() {
            override fun componentResized(e: ComponentEvent?) {
                updateColumnProportions()
            }
        })

        Burp.Montoya.userInterface().applyThemeToComponent(this)
    }

    val scrollPane: JScrollPane = JScrollPane(table).apply {
        verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        preferredSize = Dimension(0, defaultViewportHeight())
        addComponentListener(object : ComponentAdapter() {
            override fun componentResized(e: ComponentEvent?) {
                table.updateColumnProportions()
            }
        })
    }

    fun setResults(newResults: List<TestResult>) {
        val selectedName = selectedResultName()
        suppressSelectionEvents = true
        try {
            results.clear()
            results.addAll(newResults)
            fireTableDataChanged()
            table.updateColumnProportions()
            restoreSelection(selectedName)
        } finally {
            suppressSelectionEvents = false
        }
    }

    private fun selectedResultName(): String? {
        val viewRow = table.selectedRow
        if (viewRow < 0) return null
        val modelRow = table.convertRowIndexToModel(viewRow)
        if (modelRow !in results.indices) return null
        return results[modelRow].name
    }

    private fun restoreSelection(selectedName: String?) {
        if (selectedName == null) return
        val modelRow = results.indexOfFirst { it.name == selectedName }
        if (modelRow < 0) return
        val viewRow = table.convertRowIndexToView(modelRow)
        if (viewRow < 0) return
        table.selectionModel.setSelectionInterval(viewRow, viewRow)
        onResultSelected(results[modelRow])
    }

    fun getResults(): List<TestResult> = results.toList()

    fun defaultViewportHeight(): Int = ROW_HEIGHT * DEFAULT_VISIBLE_ROWS + table.tableHeader.preferredSize.height

    override fun getRowCount(): Int = results.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
        val result = results[rowIndex]
        return when (columnIndex) {
            0 -> result.name
            1 -> result.status
            else -> null
        }
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return if (columnIndex == 1) TestStatus::class.java else String::class.java
    }

    private fun JTable.updateColumnProportions() {
        val width = if (parent != null) parent.width else width
        if (width <= 0) return
        val testWidth = (width * 0.7).toInt().coerceAtLeast(120)
        columnModel.getColumn(0).preferredWidth = testWidth
        columnModel.getColumn(1).preferredWidth = (width - testWidth).coerceAtLeast(100)
    }

    private fun modelRow(table: JTable, viewRow: Int): Int {
        if (viewRow < 0) return -1
        return table.convertRowIndexToModel(viewRow)
    }

    private inner class HeaderRenderer : DefaultTableCellRenderer() {
        init {
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, borderColor()),
                BorderFactory.createEmptyBorder(4, 12, 4, 8),
            )
        }

        override fun getTableCellRendererComponent(
            table: JTable?,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int,
        ): Component {
            val component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            font = font.deriveFont(Font.BOLD, 12f)
            foreground = mutedTextColor()
            background = table?.background ?: component.background
            horizontalAlignment = SwingConstants.CENTER
            return component
        }
    }

    private inner class NameCellRenderer : DefaultTableCellRenderer() {
        init {
            horizontalAlignment = SwingConstants.LEFT
        }

        override fun getTableCellRendererComponent(
            table: JTable?,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int,
        ): Component {
            val component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            val modelRow = table?.let { modelRow(it, row) } ?: row
            if (modelRow !in results.indices) return component

            border = BorderFactory.createEmptyBorder(4, 10, 4, 10)
            val status = results[modelRow].status
            font = when (status) {
                TestStatus.RUNNING -> font.deriveFont(Font.BOLD)
                else -> font.deriveFont(Font.PLAIN, 12f)
            }

            if (!isSelected) {
                background = rowBackground(modelRow)
                foreground = primaryTextColor()
            }
            return component
        }
    }

    private inner class StatusBadgeRenderer : DefaultTableCellRenderer() {
        init {
            horizontalAlignment = SwingConstants.CENTER
        }

        override fun getTableCellRendererComponent(
            table: JTable?,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int,
        ): Component {
            val status = value as? TestStatus ?: TestStatus.UNCERTAIN
            val modelRow = table?.let { modelRow(it, row) } ?: row
            val label = if (modelRow in results.indices) results[modelRow].displayStatus() else status.label
            val badge = badgeColors(status)
            val component = super.getTableCellRendererComponent(table, label, isSelected, hasFocus, row, column)

            border = BorderFactory.createEmptyBorder(6, 6, 6, 6)

            if (!isSelected) {
                background = if (modelRow in results.indices) rowBackground(modelRow) else table?.background
            }

            putClientProperty("html.disable", null)
            text = """
                <html><body style='margin:0;padding:0;text-align:center'>
                <span style='background-color:rgb(${badge.background.red},${badge.background.green},${badge.background.blue});
                color:rgb(${badge.foreground.red},${badge.foreground.green},${badge.foreground.blue});
                padding:4px 12px;font-weight:bold;font-size:11px'>${ProbeUtils.htmlEscape(label)}</span>
                </body></html>
            """.trimIndent()
            return component
        }
    }

    private data class BadgeColors(val background: Color, val foreground: Color)

    companion object {
        const val DEFAULT_VISIBLE_ROWS = 12
        const val ROW_HEIGHT = 24

        fun statusColor(status: TestStatus): Color = badgeColors(status).foreground

        private fun badgeColors(status: TestStatus): BadgeColors {
            val dark = Burp.isDarkMode()
            return when (status) {
                TestStatus.PENDING -> if (dark) {
                    BadgeColors(Color(66, 66, 66), Color(189, 189, 189))
                } else {
                    BadgeColors(Color(238, 238, 238), Color(97, 97, 97))
                }
                TestStatus.RUNNING -> if (dark) {
                    BadgeColors(Color(21, 101, 192), Color(187, 222, 251))
                } else {
                    BadgeColors(Color(227, 242, 253), Color(13, 71, 161))
                }
                TestStatus.VULNERABLE -> if (dark) {
                    BadgeColors(Color(183, 28, 28), Color(255, 205, 210))
                } else {
                    BadgeColors(Color(255, 235, 238), Color(183, 28, 28))
                }
                TestStatus.NOT_VULNERABLE -> if (dark) {
                    BadgeColors(Color(27, 94, 32), Color(200, 230, 201))
                } else {
                    BadgeColors(Color(232, 245, 233), Color(27, 94, 32))
                }
                TestStatus.UNCERTAIN -> if (dark) {
                    BadgeColors(Color(245, 127, 23), Color(255, 243, 224))
                } else {
                    BadgeColors(Color(255, 243, 224), Color(230, 81, 0))
                }
                TestStatus.INACCESSIBLE -> if (dark) {
                    BadgeColors(Color(40, 53, 147), Color(197, 202, 233))
                } else {
                    BadgeColors(Color(232, 234, 246), Color(26, 35, 126))
                }
                TestStatus.IDENTIFIED -> if (dark) {
                    BadgeColors(Color(21, 101, 192), Color(187, 222, 251))
                } else {
                    BadgeColors(Color(227, 242, 253), Color(13, 71, 161))
                }
                TestStatus.CANCELLED -> if (dark) {
                    BadgeColors(Color(69, 90, 100), Color(207, 216, 220))
                } else {
                    BadgeColors(Color(236, 239, 241), Color(55, 71, 79))
                }
            }
        }

        fun rowBackground(rowIndex: Int): Color {
            val dark = Burp.isDarkMode()
            return if (rowIndex % 2 == 0) {
                if (dark) Color(43, 43, 43) else Color(255, 255, 255)
            } else {
                if (dark) Color(48, 48, 48) else Color(250, 250, 252)
            }
        }

        fun primaryTextColor(): Color {
            return if (Burp.isDarkMode()) Color(230, 230, 230) else Color(33, 33, 33)
        }

        fun mutedTextColor(): Color {
            return if (Burp.isDarkMode()) Color(158, 158, 158) else Color(117, 117, 117)
        }

        fun borderColor(): Color {
            return if (Burp.isDarkMode()) Color(70, 70, 70) else Color(224, 224, 224)
        }
    }
}
