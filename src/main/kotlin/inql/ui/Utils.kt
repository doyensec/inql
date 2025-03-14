package inql.ui

import burp.Burp
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import com.formdev.flatlaf.extras.FlatSVGIcon
import com.formdev.flatlaf.extras.components.FlatStyleableComponent
import com.formdev.flatlaf.extras.components.FlatTabbedPane
import inql.Logger
import java.awt.*
import java.awt.event.ItemListener
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.InputStream
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

open class FlatPanel : JPanel(), FlatStyleableComponent

open class FlowPanel(val alignment: Int, val gap: Int = 5) : FlatPanel() {
    init {
        if (alignment < FlowLayout.LEFT || alignment > FlowLayout.TRAILING) throw Exception("FlowPanel called with wrong alignment value: $alignment")
        val hgap = if (alignment < FlowLayout.LEADING) gap else 0
        val vgap = if (alignment >= FlowLayout.LEADING || alignment == FlowLayout.CENTER) gap else 0
        this.layout = FlowLayout(alignment, hgap, vgap)
    }
}

open class BoxPanel(val axis: Int, val gap: Int = 5, vararg components: Component) : FlatPanel() {
    init {
        if (axis < BoxLayout.X_AXIS || axis > BoxLayout.PAGE_AXIS) throw Exception("BoxPanel called with wrong axis value: $axis")
        this.layout = BoxLayout(this, axis)
        components.forEach { c ->
            this.add(c)
            if (gap > 0) {
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

class TextField(description: String, val columns: Int = 20) :
    Input<JTextField>(JTextField(columns), description) {

    var changeListener: (() -> Unit)? = null

    init {
        val listener = SimpleDocumentListener { this.changeHandler() }
        this.component.document.addDocumentListener(listener)
    }

    fun getText(): String = this.component.text
    fun setText(text: String) {
        this.component.text = text
    }

    class SimpleDocumentListener(val callback: () -> Unit) : DocumentListener {
        override fun insertUpdate(e: DocumentEvent?) = this.callback()
        override fun removeUpdate(e: DocumentEvent?) = this.callback()
        override fun changedUpdate(e: DocumentEvent?) = this.callback()
    }

    private fun changeHandler() {
        if (this.changeListener != null) this.changeListener!!()
    }
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

open class InQLTabbedPane: TabbedPane() {
    init {
        tabbedPane.apply {
            // Add "Settings" button on the right end
            setTrailingComponent(
                BorderPanel(-2, 0, 2, 0).apply {
                    add(SettingsTabButton())
                }
            )
        }
    }
}


open class TabbedPane(val editable: Boolean = false) : BorderPanel(0, 0) {
    val tabbedPane = FlatTabbedPane()

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

fun loadSvgIcon(resourcePath: String, height: Int): FlatSVGIcon? {
    // Attempt to get the resource as a stream; if null, return null early.
    val stream: InputStream = FlatSVGIcon::class.java.classLoader.getResourceAsStream(resourcePath) ?: return null

    // Create the SVG icon from the stream.
    val svgIcon = FlatSVGIcon(stream)

    // Calculate the scaling factor based on desired height and original icon height.
    val scalingFactor = height.toFloat() / svgIcon.iconHeight.toFloat()

    // Return a new svgIcon derived with the scaling factor, or null if the original icon had a height of 0 to prevent division by zero.
    return if (svgIcon.iconHeight > 0) svgIcon.derive(scalingFactor) else null
}

class SettingsTabButton() : JPanel() {
    val text = "Settings"
    val resourcePath = "resources/Media/svg/settings.svg"

    init {
        layout = FlowLayout(FlowLayout.LEFT, 5, 0)
        isOpaque = false // Make the panel transparent

        // Add a vertical separator at the left-most part
        val separator = JLabel("|").apply {
            foreground = Color.LIGHT_GRAY
        }
        add(separator)

        // Adding some horizontal space
        add(Box.createHorizontalStrut(4))

        // Add the clickable part
        val clickablePart = JPanel()

        // Load and add the SVG icon (note: the path is relative to the resources directory in the *Burp* JAR file)
        val icon = loadSvgIcon(resourcePath, this.preferredSize.height)
        icon?.let {
            val iconLabel = JLabel(it)
            clickablePart.add(iconLabel)
        }

        // Add the text label
        val textLabel = JLabel(text)
        clickablePart.add(textLabel)

        clickablePart.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent?) {
                SwingUtilities.invokeLater {
                    SettingsWindow.getInstance().isVisible = true
                }
            }
        })
        add(clickablePart)
    }

    private fun autoScale(icon: FlatSVGIcon): FlatSVGIcon {
        val height = this.preferredSize.height
        val scalingFactor = height.toFloat() / icon.iconHeight
        return icon.derive(scalingFactor)
    }
}

class ErrorDialog(val msg: String) {
    init {
        Logger.error(msg)
        val burpWindow = Burp.Montoya.userInterface().swingUtils().suiteFrame()
        JOptionPane.showMessageDialog(burpWindow, msg, "InQL Error", JOptionPane.ERROR_MESSAGE)
    }
}
