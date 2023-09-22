package inql.ui

import burp.Burp
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import inql.Logger
import java.awt.*
import java.awt.event.ItemListener
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*
import javax.swing.event.ChangeListener
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import kotlin.math.min

class Label(text: String, bold: Boolean = false, big: Boolean = false) : JLabel(text) {
    init {
        isOpaque = false
        if (big) {
            this.font = this.font.deriveFont(this.font.size + 5.0.toFloat()).deriveFont(Font.BOLD)
        } else if (bold) {
            this.font = this.font.deriveFont(Font.BOLD)
        }
    }

    fun withPanel(border: Int = 0): JPanel {
        return BorderPanel(border).also { it.add(this) }
    }
}

class MultilineLabel(text: String) : JTextArea(text) {
    init {
        isEditable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
    }
}

open class BorderPanel(val top: Int, val left: Int, val bottom: Int, val right: Int) : JPanel(BorderLayout()) {
    init {
        this.border = BorderFactory.createEmptyBorder(top, left, bottom, right)
    }

    constructor() : this(5, 5, 5, 5)
    constructor(border: Int) : this(border, border, border, border)
    constructor(vertical: Int, horizontal: Int) : this(vertical, horizontal, vertical, horizontal)
}

open class FlowPanel(val alignment: Int, val gap: Int = 5) : JPanel() {
    init {
        if (alignment < FlowLayout.LEFT || alignment > FlowLayout.TRAILING) throw Exception("FlowPanel called with wrong alignment value: $alignment")
        val hgap = if (alignment < FlowLayout.LEADING) gap else 0
        val vgap = if (alignment >= FlowLayout.LEADING || alignment == FlowLayout.CENTER) gap else 0
        this.layout = FlowLayout(alignment, hgap, vgap)
    }
}

class BoxPanel(val axis: Int, val gap: Int = 5, vararg components: Component) : JPanel() {
    init {
        if (axis < BoxLayout.X_AXIS || axis > BoxLayout.PAGE_AXIS) throw Exception("BoxPanel called with wrong axis value: $axis")
        this.layout = BoxLayout(this, axis)
        components.forEach { c ->
            this.add(c)
            this.add(
                if (axis == BoxLayout.X_AXIS) {
                    Box.createHorizontalStrut(gap)
                } else {
                    Box.createVerticalStrut(
                        gap,
                    )
                },
            )
        }
    }
}

open class Input<out T : JComponent>(val component: T, val description: String = "") :
    FlowPanel(FlowLayout.LEFT, gap = 5) {
    init {
        if (description != "") {
            this.add(JLabel("$description:"))
        }
        this.add(component)
    }

    override fun isEnabled(): Boolean = this.component.isEnabled
    override fun setEnabled(enabled: Boolean) {
        this.component.isEnabled = enabled
    }
}

class CheckBox(description: String, selected: Boolean = false, disabled: Boolean = false) :
    Input<JCheckBox>(JCheckBox(description, selected), "") {
    init {
        this.component.isEnabled = !disabled
    }

    fun isSelected(): Boolean = this.component.isSelected
    fun setSelected(selected: Boolean) {
        this.component.isSelected = selected
    }

    fun addItemListener(il: ItemListener) = this.component.addItemListener(il)
}

class ComboBox(description: String, vararg items: String) :
    Input<JComboBox<String>>(JComboBox<String>(items), description) {

    fun getSelectedItem(): String = this.component.selectedItem as String
    fun getSelectedIndex(): Int = this.component.selectedIndex
    fun setSelectedItem(item: String) {
        this.component.selectedItem = item
    }

    fun setSelectedIndex(index: Int) {
        this.component.selectedIndex = index
    }

    fun addItemListener(il: ItemListener) = this.component.addItemListener(il)
}

class Spinner(description: String, min: Int, val max: Int, val step: Int = 1) :
    Input<JSpinner>(JSpinner(SpinnerNumberModel(min, min, max, step)), description) {

    fun getValue(): Int = this.component.value as Int
    fun setValue(value: Int) {
        this.component.value = value
    }

    fun addChangeListener(cl: ChangeListener) = this.component.addChangeListener(cl)
}

class TextArea(description: String, val rows: Int, val cols: Int) :
    FlowPanel(FlowLayout.LEFT, gap = 5) {

    val component = JTextArea(rows, cols)
    var changeListener: (() -> Unit)? = null

    init {
        this.component.isEditable = true
        this.component.isOpaque = true

        this.component.lineWrap = true
        this.component.wrapStyleWord = true

        val listener = SimpleDocumentListener { this.changeHandler() }
        this.component.document.addDocumentListener(listener)

        val scrollable = JScrollPane(this.component)
        scrollable.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        scrollable.horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED

        if (description != "") {
            val label = BorderPanel(0).also { it.add(JLabel(description)) }
            val bordered = BorderPanel(0, 10).add(scrollable)
            val boxed = BoxPanel(BoxLayout.Y_AXIS, gap = 5, label, bordered)
            this.add(boxed)
        } else {
            this.add(scrollable)
        }
    }

    fun getText(): String = this.component.text
    fun setText(text: String) {
        this.component.text = text
    }

    override fun isEnabled(): Boolean = this.component.isEnabled
    override fun setEnabled(enabled: Boolean) {
        this.component.isEnabled = enabled
    }

    class SimpleDocumentListener(val callback: () -> Unit) : DocumentListener {
        override fun insertUpdate(e: DocumentEvent?) = this.callback()
        override fun removeUpdate(e: DocumentEvent?) = this.callback()
        override fun changedUpdate(e: DocumentEvent?) = this.callback()
    }

    private fun changeHandler() {
        if (this.component.lineCount > this.rows) this.component.rows = this.rows
        if (this.changeListener != null) this.changeListener!!()
    }
}

open class TabbedPane : BorderPanel() {
    val tabbedPane = JTabbedPane()

    init {
        this.add(this.tabbedPane)
    }

    open fun addTab(title: String, component: JComponent) {
        this.tabbedPane.addTab(title, component)
    }
}

/* Create a window (JFrame) with reasonable defaults. */
open class Window(val windowTitle: String) : JFrame(windowTitle) {
    init {
        this.defaultCloseOperation = DISPOSE_ON_CLOSE
        this.layout = BorderLayout()
    }

    fun autoSize() {
        val preferredSize = this.preferredSize
        val screenHeight = Toolkit.getDefaultToolkit().screenSize.height
        val reasonableHeight = min(preferredSize.height, screenHeight - 50)
        this.preferredSize = Dimension(preferredSize.width, reasonableHeight)

        // Set the maximum size of the frame to match its content
        this.maximumSize = Dimension(preferredSize.width, preferredSize.height)

        // Set the minimum size to something reasonable as well
        this.minimumSize = Dimension(preferredSize.width, 400)

        // Pack the window to fit its content
        this.pack()

        // Center the window on the screen
        this.setLocationRelativeTo(null)
    }
}

open class MessageEditor(val readOnly: Boolean = false) : JTabbedPane() {
    val request: HttpRequestEditor
    val response: HttpResponseEditor

    init {
        if (readOnly) {
            request = Burp.Montoya.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
            response = Burp.Montoya.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
        } else {
            request = Burp.Montoya.userInterface().createHttpRequestEditor()
            response = Burp.Montoya.userInterface().createHttpResponseEditor()
        }
        this.addTab("Request", request.uiComponent())
        this.addTab("Response", response.uiComponent())
    }
}

class Icon(val normal: Image, val hover: Image?, val selected: Image?)

class ImgButton(val fallback: String, displayIcon: Icon?) : JButton() {
    private var normalIcon: ImageIcon? = null
    private var hoverIcon: ImageIcon? = null
    private var selectedIcon: ImageIcon? = null

    init {
        this.border = BorderFactory.createEmptyBorder()
        this.text = fallback
        if (displayIcon?.normal != null) {
            this.normalIcon = ImageIcon(autoResize(displayIcon.normal))
            this.icon = normalIcon
            this.text = null
            if (displayIcon.hover != null) {
                this.hoverIcon = ImageIcon(autoResize(displayIcon.hover))
                this.addMouseListener(ImageHoverListener(this))
            }
            if (displayIcon.selected != null) {
                this.selectedIcon = ImageIcon(autoResize(displayIcon.selected))
                this.addMouseListener(ImageClickListener(this))
            }
        }
    }

    fun hover(active: Boolean) {
        if (active) {
            this.icon = this.hoverIcon
        } else {
            this.icon = this.normalIcon
        }
    }

    fun selected(active: Boolean) {
        if (active) {
            this.icon = this.selectedIcon
        } else {
            this.icon = this.normalIcon
        }
    }

    private fun autoResize(src: Image): Image {
        val sz = this.preferredSize.height - this.insets.top
        return src.getScaledInstance(sz, sz, Image.SCALE_SMOOTH)
    }

    class ImageHoverListener(private val btn: ImgButton) : MouseAdapter() {
        override fun mouseEntered(e: MouseEvent?) {
            super.mouseEntered(e)
            btn.hover(true)
        }

        override fun mouseExited(e: MouseEvent?) {
            super.mouseExited(e)
            btn.hover(false)
        }
    }

    class ImageClickListener(private val btn: ImgButton) : MouseAdapter() {
        override fun mousePressed(e: MouseEvent?) {
            super.mousePressed(e)
            btn.selected(true)
        }

        override fun mouseReleased(e: MouseEvent?) {
            super.mouseReleased(e)
            btn.selected(false)
        }
    }
}

class ErrorDialog(val msg: String) {
    init {
        Logger.error(msg)
        val burpWindow = Burp.Montoya.userInterface().swingUtils().suiteFrame()
        JOptionPane.showMessageDialog(burpWindow, msg, "InQL Error", JOptionPane.ERROR_MESSAGE)
    }
}
