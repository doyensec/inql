package inql.attacker

import java.net.URL
import javax.swing.JTable
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableModel

class HistoryLog(private val attacks: ArrayList<Attack>, tableSelectionListener: (Int) -> Unit) : AbstractTableModel() {

    private val COLUMNS = listOf<String>(
        "Date",
        "Host",
        "Path",
        "Status",
        "Length",
        "From",
        "To"
    )

    val table = HistoryLogTable(this, tableSelectionListener)
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
            1 -> URL(entry.req.url()).host
            2 -> entry.req.path()
            3 -> entry.resp?.statusCode()
            4 -> entry.resp?.body()?.length()
            5 -> entry.start
            6 -> entry.end
            else -> null
        }
    }

    class HistoryLogTable(model: TableModel, val tableSelectionListener: (Int) -> Unit) : JTable(model) {
        override fun changeSelection(rowIndex: Int, columnIndex: Int, toggle: Boolean, extend: Boolean) {
            this.tableSelectionListener(rowIndex)
            super.changeSelection(rowIndex, columnIndex, toggle, extend)
        }
    }

}