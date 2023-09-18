package inql.ui

import java.awt.*
import java.awt.event.*
import javax.swing.*
import javax.swing.event.ChangeEvent
import javax.swing.event.ChangeListener
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class EditableTabTitle(title: String, val component: Component) : JTextField(title) {
    private val changeListeners = ArrayList<(EditableTabTitle) -> Unit>()
    private var valueBeforeChange = this.text

    fun addChangeListener(listener: (EditableTabTitle) -> Unit) {
        this.changeListeners.add(listener)
    }

    fun autoSize() {
        val textWidth = this.getFontMetrics(this.font).stringWidth(this.text)
        this.preferredSize = Dimension(textWidth + 5, this.preferredSize.height)
    }

    fun enterEditingMode() {
        this.isOpaque = true
        this.isEditable = true
        this.valueBeforeChange = this.text
        this.requestFocusInWindow()
        this.selectAll()
    }

    fun exitEditingMode() {
        this.isOpaque = false
        this.isEditable = false
        this.transferFocusUpCycle()
        if (this.valueBeforeChange != this.text) {
            this.changeListeners.forEach { it(this) }
        }
        this.autoSize()
    }

    init {
        this.border = BorderFactory.createEmptyBorder()
        this.document.addDocumentListener(AutoSizeListener(this))
        this.exitEditingMode()
        this.addActionListener {
            this.exitEditingMode()
        }
        this.addFocusListener(FocusHandler())
        this.addMouseListener(TabTitleMouseAdapter())
    }

    class AutoSizeListener(val title: EditableTabTitle) : DocumentListener {
        override fun insertUpdate(e: DocumentEvent?) {
            title.autoSize()
        }

        override fun removeUpdate(e: DocumentEvent?) {
            // Do nothing
        }

        override fun changedUpdate(e: DocumentEvent?) {
            // Do nothing
        }

    }

    class FocusHandler : FocusAdapter() {
        override fun focusLost(e: FocusEvent?) {
            (e?.component as EditableTabTitle).exitEditingMode()
        }
    }

    class TabTitleMouseAdapter : TabMouseAdapter() {
        override fun mouseClicked(e: MouseEvent?) {
            super.mouseClicked(e)
            if (e!!.clickCount >= 2) {
                (e.component as EditableTabTitle).enterEditingMode()
            }
        }

        override fun mousePressed(e: MouseEvent?) {
            super.mousePressed(e)
            (e!!.component as EditableTabTitle).exitEditingMode()
        }
    }

    // https://stackoverflow.com/a/53034794
    open class TabMouseAdapter : MouseListener {
        override fun mouseClicked(e: MouseEvent?) {
            redispatch(e)
        }

        override fun mousePressed(e: MouseEvent?) {
            redispatch(e)
        }

        override fun mouseReleased(e: MouseEvent?) {
            redispatch(e)
        }

        override fun mouseEntered(e: MouseEvent?) {
            redispatch(e)
        }

        override fun mouseExited(e: MouseEvent?) {
            redispatch(e)
        }

        private fun redispatch(e: MouseEvent?) {
            if (e == null) return
            val source = e.component
            var target = source.parent
            while (true) {
                if (target == null) break
                if (target is JTabbedPane) break
                target = target.parent
            }
            if (target == null) return
            val targetEvent = SwingUtilities.convertMouseEvent(source, e, target)
            target.dispatchEvent(targetEvent)
        }
    }
}

class EditableTab(val tabTitle: EditableTabTitle, showClose: Boolean = true) : FlowPanel(FlowLayout.LEFT, gap = 0) {
    constructor(title: String, component: Component, showClose: Boolean = true) : this(
        EditableTabTitle(
            title,
            component
        ), showClose
    )

    val closeButton = JButton("⨉")
    var showing = showClose
    val closeListeners = ArrayList<(EditableTab) -> Unit>()

    init {
        this.border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
        this.isOpaque = false
        this.closeButton.isOpaque = false
        this.closeButton.isContentAreaFilled = false
        this.closeButton.isBorderPainted = false
        this.closeButton.iconTextGap = 0
        this.closeButton.margin = Insets(0, 0, 0, 0)
        this.closeButton.addActionListener {
            this.closeListeners.forEach { it(this) }
        }
        this.showCloseButton(showClose)
        this.add(tabTitle)
        if (showClose) this.add(closeButton)
    }

    fun showCloseButton(show: Boolean) {
        if (show && !showing) {
            this.showing = true
            this.add(closeButton)
        } else if (!show && showing) {
            this.showing = false
            this.remove(this.closeButton)
        }
    }

    fun addCloseListener(listener: (EditableTab) -> Unit) {
        this.closeListeners.add(listener)
    }
}

interface ITabComponentFactory {
    fun createComponent(idx: Int): JComponent
    fun getNewTabTitle(idx: Int, c: JComponent): String
}

open class EditableTabbedPane : TabbedPane() {
    private var tabComponentFactory: ITabComponentFactory? = null
    private val changeListeners = ArrayList<(EditableTabTitle) -> Unit>()
    private val newTabButtonPresent: Boolean
        get() = this.tabComponentFactory != null
    val tabCount: Int
        get() {
            var count = this.tabbedPane.tabCount
            // Do not count the "New Tab" tab as a real tab
            if (this.newTabButtonPresent) count--
            return count
        }

    val tabs: List<Component>
        get() {
            val cnt = this.tabCount
            val lst = ArrayList<Component>(cnt)
            for (idx in 0..<cnt) {
                lst.add(this.tabbedPane.getComponentAt(idx))
            }
            return lst
        }

    // Index of the "New Tab" tab
    val newTabIdx: Int
        get() {
            if (!this.newTabButtonPresent) return -1
            return this.tabCount
        }

    fun setTabComponentFactory(tabFactory: ITabComponentFactory) {
        if (this.tabComponentFactory != null) throw Exception("TabComponentFactory already set")
        this.tabComponentFactory = tabFactory
        this.addNewTabButton()
    }

    private fun addNewTabButton() {
        val panel = JPanel().also { it.add(JLabel("You should not really be able to see this")) }
        this.tabbedPane.addTab("+", panel)
        val plusLabel = JLabel("+").also {
            it.font = it.font.deriveFont(Font.BOLD)
        }
        this.tabbedPane.setTabComponentAt(this.tabbedPane.tabCount - 1, plusLabel)
        this.tabbedPane.addMouseListener(NewTabClickHandler(this))
        this.tabbedPane.addChangeListener(NewTabChangeListener(this))
    }

    override fun addTab(title: String, component: JComponent) {
        val idx = this.tabCount
        this.insertTab(title, component, idx)
    }

    fun insertTab(title: String, component: JComponent, idx: Int) {
        val editableTitle = EditableTabTitle(title, component)
        this.changeListeners.forEach { editableTitle.addChangeListener(it) }
        val tab = EditableTab(editableTitle)
        tab.addCloseListener { this.closeTabHandler(it) }
        this.tabbedPane.insertTab(title, null, component, null, idx)
        this.tabbedPane.setTabComponentAt(idx, tab)
    }

    fun newTab(): JComponent {
        if (!newTabButtonPresent) throw Exception("Trying to invoke new tab creation without TabComponentFactory present")
        val idx = this.tabCount
        val component = this.tabComponentFactory!!.createComponent(idx)
        val title = this.tabComponentFactory!!.getNewTabTitle(idx, component)
        this.insertTab(title, component, idx)
        this.tabbedPane.selectedIndex = idx
        return component
    }

    fun addTitleChangeListener(listener: (EditableTabTitle) -> Unit) {
        this.changeListeners.add(listener)
        for (i in 0 until this.tabbedPane.tabCount) {
            val tab = this.tabbedPane.getTabComponentAt(i)
            if (tab is EditableTab) {
                tab.tabTitle.addChangeListener(listener)
            }
        }
    }

    private fun closeTabHandler(tab: EditableTab) {
        this.closeTab(this.tabbedPane.indexOfTabComponent(tab))
    }

    open fun closeTab(idx: Int) {
        this.tabbedPane.removeTabAt(idx)
    }

    fun closeAllTabs() {
        for (idx in 0..<this.tabCount) {
            this.closeTab(idx)
        }
    }

    class NewTabClickHandler(private val pane: EditableTabbedPane) : MouseAdapter() {
        override fun mousePressed(e: MouseEvent?) {
            super.mousePressed(e)
            if (e == null) return
            if (pane.tabbedPane.indexAtLocation(e.x, e.y) == pane.newTabIdx) {
                pane.newTab()
            }
        }
    }

    class NewTabChangeListener(private val pane: EditableTabbedPane) : ChangeListener {
        override fun stateChanged(e: ChangeEvent?) {
            if (e == null) return
            if (pane.tabbedPane.selectedIndex == pane.newTabIdx) {
                if (pane.tabCount == 0) {
                    // Create a new tab if all tabs have been closed
                    pane.newTab()
                } else {
                    // Else focus the last available tab
                    pane.tabbedPane.selectedIndex = pane.tabCount - 1
                }
            }
        }
    }
}