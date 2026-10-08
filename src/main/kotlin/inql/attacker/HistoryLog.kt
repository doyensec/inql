package inql.attacker

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.URI
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableModel

class HistoryLog(
    private val attacks: ArrayList<Attack>,
    tableSelectionListener: (Int) -> Unit,
    private val onDeleteSelected: (List<Attack>) -> Unit,
    private val onClear: () -> Unit,
) : AbstractTableModel() {

    private val COLUMNS = listOf(
        "Date",
        "Host",
        "Path",
        "Status",
        "Length",
        "Response time (ms)",
        "Mode",
        "Items",
        "Part",
    )

    val table = HistoryLogTable(this, tableSelectionListener).also { table ->
        table.selectionModel.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        table.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                if (e.isPopupTrigger) showPopup(e)
            }

            override fun mouseReleased(e: MouseEvent) {
                if (e.isPopupTrigger) showPopup(e)
            }

            private fun showPopup(e: MouseEvent) {
                val row = table.rowAtPoint(e.point)
                if (row >= 0 && !table.isRowSelected(row)) {
                    table.setRowSelectionInterval(row, row)
                    tableSelectionListener(row)
                }
                val selectedCount = table.selectedRowCount
                val deleteItem = JMenuItem("Delete selected").also { item ->
                    item.isEnabled = selectedCount > 0
                    item.addActionListener {
                        val selected = table.selectedRows.sortedDescending().mapNotNull { attacks.getOrNull(it) }
                        onDeleteSelected(selected)
                    }
                }
                val clearItem = JMenuItem("Clear history").also { item ->
                    item.isEnabled = attacks.isNotEmpty()
                    item.addActionListener { onClear() }
                }
                JPopupMenu().also { popup ->
                    popup.add(deleteItem)
                    popup.add(clearItem)
                    popup.show(e.component, e.x, e.y)
                }
            }
        })
    }

    override fun getRowCount(): Int {
        return this.attacks.size
    }

    override fun getColumnCount(): Int {
        return this.COLUMNS.size
    }

    override fun getColumnName(column: Int): String {
        return this.COLUMNS[column]
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
        val entry = this.attacks[rowIndex]
        return when (columnIndex) {
            0 -> entry.ts
            1 -> hostOf(entry)
            2 -> entry.req.path()
            3 -> if (entry.error != null) "Error" else entry.resp?.statusCode()
            4 -> entry.resp?.body()?.length()
            5 -> entry.responseTimeMs
            6 -> entry.mode
            7 -> entry.itemCount
            8 -> "${entry.part}/${entry.partCount}"
            else -> null
        }
    }

    private fun hostOf(entry: Attack): String {
        return try {
            URI.create(entry.req.url()).host ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    class HistoryLogTable(model: TableModel, val tableSelectionListener: (Int) -> Unit) : JTable(model) {
        override fun changeSelection(rowIndex: Int, columnIndex: Int, toggle: Boolean, extend: Boolean) {
            if (rowIndex >= 0) {
                this.tableSelectionListener(rowIndex)
            }
            super.changeSelection(rowIndex, columnIndex, toggle, extend)
        }
    }
}
