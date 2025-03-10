package inql.ui

import java.awt.*
import java.awt.event.*
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class EditableTabTitle(title: String, val component: Component) : JTextField(title) {
    private val changeListeners = ArrayList<(EditableTabTitle) -> Unit>()
    private var valueBeforeChange = this.text

    // A bunch of listeners to handle tab title change (these are fired when the title has been changed, not during editing)
    fun addChangeListener(listener: (EditableTabTitle) -> Unit) {
        this.changeListeners.add(listener)
    }

    fun autoSize() {
        val textWidth = this.getFontMetrics(this.font).stringWidth(this.text)
        this.preferredSize = Dimension(textWidth + 5, this.preferredSize.height)
        if (parent != null) {
            parent.revalidate()
        }
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
    }

    init {
        this.border = BorderFactory.createEmptyBorder()
        this.exitEditingMode()
        this.addActionListener {
            // Schedule the basic exit from editing mode, more complex logic is added elsewhere
            this.exitEditingMode()
        }
        // Enter / exit editing mode on double click
        this.addMouseListener(TabTitleMouseAdapter())
        // Exit editing mode on focus lost
        this.addFocusListener(FocusHandler())
        // Resize the tab title when the text changes
        this.document.addDocumentListener(AutoSizeListener(this))
    }

    class AutoSizeListener(val title: EditableTabTitle) : DocumentListener {
        override fun insertUpdate(e: DocumentEvent?) {
            title.autoSize()
        }

        override fun removeUpdate(e: DocumentEvent?) {
            title.autoSize()
        }

        override fun changedUpdate(e: DocumentEvent?) {
            title.autoSize()
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

class EditableTab(val tabTitle: EditableTabTitle) : BoxPanel(BoxLayout.Y_AXIS, gap = 0) {
    val closeButton = loadSvgIcon("resources/Media/svg/close.svg", 7)?.let { JButton(it) } ?: JButton("⨉")
    val closeListeners = ArrayList<(EditableTab) -> Unit>()

    private val cornerRadius = 10 // Adjust the corner radius as needed
    private val bottomBorderColor = Color(255, 102, 51) // Bottom border color
    private val bottomBorderThickness = 2 // Thickness of the bottom border
    private val background = Color(230, 230, 230)

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)

        // Step 1: Draw the bottom border - a bottom-border-colored rounded rectangle
        g2.color = bottomBorderColor
        g2.fillRoundRect(0, 0, width, height, cornerRadius, cornerRadius)

        // Step 2: Draw the main body on top, leaving only the bottom border visible
        g2.color = background
        g2.fillRoundRect(0, 0, width, height - bottomBorderThickness, cornerRadius, cornerRadius)

        // Step 3: Draw a straight-line rectangle above the bottom to ensure a straight border
        g2.fillRect(0, height - bottomBorderThickness * 3, width, bottomBorderThickness * 2)

        g2.dispose()
    }

    // Ensures that the preferred size accounts for the border
    override fun getPreferredSize(): Dimension {
        val size = super.getPreferredSize()
        size.height += bottomBorderThickness
        return size
    }

    init {
        //this.border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
        //this.isOpaque = true
        //this.style = "background: #eee; arc: 10; borderColor: #f63; borderWidth: 3; outlineColor: #f63; outline: error; error.borderColor: #f64"
        //this.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, Color(255, 102, 51)));
        this.closeButton.isOpaque = false
        this.closeButton.isContentAreaFilled = false
        this.closeButton.isBorderPainted = false
        this.closeButton.iconTextGap = 0
        this.closeButton.margin = Insets(4, 0, 0, 0)
        this.closeButton.addActionListener {
            this.closeListeners.forEach { it(this) }
        }

        val upper = BoxPanel(BoxLayout.X_AXIS, gap = 0)
        upper.isOpaque = false
        upper.add(tabTitle)
        upper.add(this.closeButton)
        upper.border = BorderFactory.createEmptyBorder(2, 10, 2, 10)
        add(upper)

//        val lower = BoxPanel(BoxLayout.X_AXIS, gap = 0)
//        lower.border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
//        lower.add(FlatPanel().apply {
//            isOpaque = true
//            style = "background: #f63; height: 1; insets: 0,0,0,0"// foreground: #f63; height: 3"
//            maximumSize = Dimension(Integer.MAX_VALUE, 1) // 3 pixels high, full width
//            //minimumSize = Dimension(0, 15)
//            //foreground = Color.ORANGE // Color of the separator
//            //background = Color.ORANGE // Needed if the separator isn't showing up
//        })
//        add(lower)
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
    private val tabFactoryInitiated: Boolean
        get() = this.tabComponentFactory != null
    val tabCount: Int
        get() {
            var count = this.tabbedPane.tabCount
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

    init {
        tabbedPane.apply {
            setTabAreaInsets(Insets(0, 0, 0, 0))
            setTabInsets(Insets(0, 4, 2, 3))
            style = "tabSelectionHeight: 0"

            // Add "New Tab" button on the right
            setTrailingComponent(
                BorderPanel(-2, 0, 2, 0).apply {
                    add(FlowPanel(FlowLayout.LEFT, 0).apply {
                        val panel = JPanel()

                        val icon = loadSvgIcon("resources/Media/svg/add.svg", 17)
                        icon?.let {
                            panel.add(JLabel(icon))
                        } ?: panel.add(JLabel("+"))
                        //panel.add(JLabel("+"))
                        panel.addMouseListener(object : MouseAdapter() {
                            override fun mouseClicked(e: MouseEvent?) {
                                newTab()
                            }
                        })
                        add(panel)
                    })
                }
            )
        }
    }

    fun setTabComponentFactory(tabFactory: ITabComponentFactory) {
        if (this.tabComponentFactory != null) throw Exception("TabComponentFactory already set")
        this.tabComponentFactory = tabFactory
    }

    override fun addTab(title: String, component: JComponent) {
        this.insertTab(title, component, this.tabCount)
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
        if (!tabFactoryInitiated) throw Exception("Trying to invoke new tab creation without TabComponentFactory present")
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
            this.closeTab(0)
        }
    }
}
