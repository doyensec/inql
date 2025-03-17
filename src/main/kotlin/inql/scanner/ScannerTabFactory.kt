package inql.scanner

import inql.ui.ITabComponentFactory
import javax.swing.JComponent

class ScannerTabFactory(val scanner: Scanner, var tabIdx: Int = 0) : ITabComponentFactory {
    override fun createComponent(idx: Int): JComponent {
        return ScannerTab(scanner, tabIdx++)
    }

    override fun getNewTabTitle(idx: Int, c: JComponent): String {
        if (c !is ScannerTab) throw Exception("The passed component is not a ScannerTab instance")
        return if (c.linkedProfile != null) "${c.id} [${c.linkedProfile!!.name}]" else "${c.id}"
    }
}
