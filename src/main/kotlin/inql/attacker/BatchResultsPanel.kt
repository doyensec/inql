package inql.attacker

import inql.graphql.formatting.Style
import inql.ui.SimpleDocumentListener
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Color
import java.awt.Component
import java.awt.FlowLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.regex.Pattern
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.RowFilter
import javax.swing.SwingConstants
import javax.swing.border.EmptyBorder
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableCellRenderer
import javax.swing.table.TableRowSorter

/**
 * Per-item results of the batch attack that the selected history row belongs to, merged across all of the
 * attack's HTTP requests. Rare outcomes are highlighted, so e.g. the one accepted OTP stands out.
 */
class BatchResultsPanel : JPanel(CardLayout()) {
    private var run: BatchRun? = null
    private val resultsModel = ResultsTableModel()
    private val table = object : JTable(resultsModel) {
        override fun prepareRenderer(renderer: TableCellRenderer, row: Int, column: Int): Component {
            val component = super.prepareRenderer(renderer, row, column)
            if (!isRowSelected(row)) {
                val item = resultsModel.itemAt(convertRowIndexToModel(row))
                val outlier = item != null && run?.isOutlier(item) == true
                component.background = if (outlier) highlight(background) else background
            }
            return component
        }
    }
    private val filterField = JTextField(18)
    private val outliersOnly = JCheckBox("Highlighted only")
    private val summaryLabel = JLabel()
    private val placeholder = JLabel("", SwingConstants.CENTER)

    /** Called when a result row is selected. */
    var onItemSelected: ((BatchRun, BatchResultItem) -> Unit)? = null

    /** Called when a result row is double-clicked. */
    var onItemActivated: ((BatchRun, BatchResultItem) -> Unit)? = null

    init {
        table.autoCreateRowSorter = false
        table.fillsViewportHeight = true
        filterField.document.addDocumentListener(SimpleDocumentListener { applyFilter() })
        filterField.toolTipText = "Show only items whose payloads or errors contain this text."
        outliersOnly.addItemListener { applyFilter() }
        table.selectionModel.addListSelectionListener { event ->
            if (event.valueIsAdjusting || table.selectedRowCount != 1) return@addListSelectionListener
            selectedItem()?.let { (run, item) -> onItemSelected?.invoke(run, item) }
        }
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount != 2 || table.rowAtPoint(e.point) < 0) return
                selectedItem()?.let { (run, item) -> onItemActivated?.invoke(run, item) }
            }
        })

        val toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).also {
            it.add(JLabel("Filter:"))
            it.add(filterField)
            it.add(outliersOnly)
            it.add(summaryLabel)
        }
        val resultsCard = JPanel(BorderLayout()).also {
            it.add(toolbar, BorderLayout.NORTH)
            it.add(JScrollPane(table), BorderLayout.CENTER)
        }
        placeholder.border = EmptyBorder(8, 8, 8, 8)
        add(resultsCard, CARD_RESULTS)
        add(placeholder, CARD_EMPTY)
        showRun(null)
    }

    /** Shows the results of [run], or a placeholder when the selected row has none. */
    fun showRun(run: BatchRun?, hasHistoryRow: Boolean = false) {
        if (run != null && run === this.run) return
        this.run = run
        resultsModel.fireTableStructureChanged()
        table.rowSorter = TableRowSorter(resultsModel)
        applyFilter()
        updateSummary()
        if (run == null) {
            placeholder.text = if (hasHistoryRow) {
                "Results are only kept for attacks sent in this session."
            } else {
                "Send a batch attack to see per-item results."
            }
        }
        (layout as CardLayout).show(this, if (run == null) CARD_EMPTY else CARD_RESULTS)
    }

    /** Must be called on the EDT after items [from]..[to] (inclusive) were added to [run]. */
    fun itemsAdded(run: BatchRun, from: Int, to: Int) {
        if (run !== this.run) return
        if (outliersOnly.isSelected) {
            // New items can change which existing items count as highlighted.
            resultsModel.fireTableDataChanged()
        } else {
            resultsModel.fireTableRowsInserted(from, to)
            table.repaint()
        }
        updateSummary()
    }

    private fun selectedItem(): Pair<BatchRun, BatchResultItem>? {
        val run = this.run ?: return null
        val row = table.selectedRow.takeIf { it >= 0 } ?: return null
        val item = resultsModel.itemAt(table.convertRowIndexToModel(row)) ?: return null
        return run to item
    }

    private fun applyFilter() {
        val sorter = table.rowSorter as? TableRowSorter<*> ?: return
        val text = filterField.text.trim()
        val pattern = if (text.isEmpty()) null else Pattern.compile(Pattern.quote(text), Pattern.CASE_INSENSITIVE)
        val onlyOutliers = outliersOnly.isSelected
        @Suppress("UNCHECKED_CAST")
        (sorter as TableRowSorter<ResultsTableModel>).rowFilter = if (pattern == null && !onlyOutliers) {
            null
        } else {
            object : RowFilter<ResultsTableModel, Int>() {
                override fun include(entry: Entry<out ResultsTableModel, out Int>): Boolean {
                    val item = resultsModel.itemAt(entry.identifier) ?: return false
                    if (onlyOutliers && run?.isOutlier(item) != true) return false
                    if (pattern == null) return true
                    return (item.payloads.filterNotNull() + item.errors).any { pattern.matcher(it).find() }
                }
            }
        }
    }

    private fun updateSummary() {
        val run = this.run ?: return
        val pending = if (run.items.size < run.totalItems) " of ${run.totalItems}" else ""
        summaryLabel.text = "${run.items.size}$pending items, ${run.outlierCount()} highlighted"
    }

    private fun highlight(base: Color): Color {
        val accent = Style.ThemeColors.Accent
        val ratio = 0.35
        return Color(
            (base.red * (1 - ratio) + accent.red * ratio).toInt(),
            (base.green * (1 - ratio) + accent.green * ratio).toInt(),
            (base.blue * (1 - ratio) + accent.blue * ratio).toInt(),
        )
    }

    /** Columns after the "#" column and the payload columns. */
    private enum class ItemColumn(val title: String, val type: Class<*>, val value: (BatchResultItem) -> Any?) {
        PART("Part", Integer::class.java, { it.part }),
        STATUS("Status", String::class.java, { it.status.label }),
        ERRORS("Errors", String::class.java, { it.errors }),
        SIZE("Size", Integer::class.java, { it.size }),
        RESPONSE_TIME("Response time (ms)", java.lang.Long::class.java, { it.responseTimeMs }),
    }

    /** Column 0 is the item number, followed by one column per batched variable, then [ItemColumn]s. */
    private inner class ResultsTableModel : AbstractTableModel() {
        private val payloadColumns: Int get() = run?.variableLabels?.size ?: 0

        fun itemAt(row: Int): BatchResultItem? = run?.items?.getOrNull(row)

        private fun itemColumn(column: Int): ItemColumn = ItemColumn.entries[column - 1 - payloadColumns]

        override fun getRowCount(): Int = run?.items?.size ?: 0

        override fun getColumnCount(): Int = 1 + payloadColumns + ItemColumn.entries.size

        override fun getColumnName(column: Int): String {
            if (column == 0) return "#"
            if (column <= payloadColumns) return run?.variableLabels?.get(column - 1) ?: ""
            return itemColumn(column).title
        }

        override fun getColumnClass(column: Int): Class<*> {
            if (column == 0) return Integer::class.java
            if (column <= payloadColumns) return String::class.java
            return itemColumn(column).type
        }

        override fun getValueAt(row: Int, column: Int): Any? {
            val item = itemAt(row) ?: return null
            if (column == 0) return item.index
            if (column <= payloadColumns) return item.payloads.getOrNull(column - 1)
            return itemColumn(column).value(item)
        }
    }

    private companion object {
        const val CARD_RESULTS = "results"
        const val CARD_EMPTY = "empty"
    }
}
