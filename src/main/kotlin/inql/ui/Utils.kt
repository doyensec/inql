package inql.ui

import burp.Burp
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import com.formdev.flatlaf.extras.FlatSVGIcon
import com.formdev.flatlaf.extras.FlatSVGIcon.ColorFilter
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

/** Word-wrapping, read-only text that looks and behaves like a [JLabel]. */
class MultilineLabel(text: String) : JTextArea(text) {
    init {
        isEditable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
        isFocusable = false
        cursor = Cursor.getDefaultCursor()
    }

    // Theme changes reinstall the text area's highlighter and font, so reapply the label look every time.
    override fun updateUI() {
        super.updateUI()
        highlighter = null
        font = UIManager.getFont("Label.font") ?: font
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

class WrapLayout(private val hgap: Int, private val rowGap: Int) : LayoutManager {
    private var lastSize: Dimension? = null

    override fun addLayoutComponent(name: String?, comp: Component?) {}

    override fun removeLayoutComponent(comp: Component?) {}

    override fun preferredLayoutSize(target: Container): Dimension = layoutSize(target, preferred = true)

    override fun minimumLayoutSize(target: Container): Dimension = layoutSize(target, preferred = false)

    override fun layoutContainer(target: Container) = synchronized(target.treeLock) {
        val insets = target.insets
        var y = insets.top
        for (row in rows(target, preferred = true)) {
            val rowHeight = row.maxOf { it.second.height }
            var x = insets.left + hgap
            for ((component, size) in row) {
                component.setBounds(x, y + (rowHeight - size.height) / 2, size.width, size.height)
                x += size.width + hgap
            }
            y += rowHeight + rowGap
        }
        val size = preferredLayoutSize(target)
        if (size != lastSize) {
            lastSize = size
            SwingUtilities.invokeLater { target.revalidate() }
        }
    }

    private fun layoutSize(target: Container, preferred: Boolean): Dimension = synchronized(target.treeLock) {
        val rows = rows(target, preferred)
        val insets = target.insets
        val width = rows.maxOfOrNull { row -> row.sumOf { it.second.width } + hgap * (row.size - 1) } ?: 0
        val height = rows.sumOf { row -> row.maxOf { it.second.height } } + rowGap * maxOf(0, rows.size - 1)
        Dimension(width + insets.left + insets.right + hgap * 2, height + insets.top + insets.bottom)
    }

    private fun rows(target: Container, preferred: Boolean): List<List<Pair<Component, Dimension>>> {
        var container: Container = target
        while (container.width == 0 && container.parent != null) container = container.parent
        val available = container.width.takeIf { it > 0 } ?: Int.MAX_VALUE
        val maxWidth = maxOf(0, available - target.insets.left - target.insets.right - hgap * 2)
        val rows = mutableListOf<MutableList<Pair<Component, Dimension>>>()
        var rowWidth = 0
        for (component in target.components) {
            if (!component.isVisible) continue
            val size = Dimension(if (preferred) component.preferredSize else component.minimumSize)
            size.width = minOf(size.width, maxWidth)
            if (rows.isEmpty() || (rowWidth > 0 && rowWidth + hgap + size.width > maxWidth)) {
                rows += mutableListOf<Pair<Component, Dimension>>()
                rowWidth = 0
            }
            if (rowWidth > 0) rowWidth += hgap
            rowWidth += size.width
            rows.last() += component to size
        }
        return rows
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
        super.setEnabled(enabled)
        this.component.isEnabled = enabled
        for (child in components) {
            child.isEnabled = enabled
        }
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

/** Commits text typed into the spinner and returns its value; invalid input keeps the last valid value. */
fun JSpinner.committedInt(): Int {
    try {
        commitEdit()
    } catch (_: java.text.ParseException) {
        // Keep last valid value when input is invalid.
    }
    return value as Int
}

class SimpleDocumentListener(val callback: () -> Unit) : DocumentListener {
    override fun insertUpdate(e: DocumentEvent?) = this.callback()
    override fun removeUpdate(e: DocumentEvent?) = this.callback()
    override fun changedUpdate(e: DocumentEvent?) = this.callback()
}

class Spinner(description: String, min: Int, val max: Int, val step: Int = 1) :
    Input<JSpinner>(JSpinner(SpinnerNumberModel(min, min, max, step)), description) {

    fun getValue(): Int = this.component.value as Int

    fun getCommittedValue(): Int = component.committedInt()

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

    private fun changeHandler() {
        if (this.component.lineCount > this.rows) this.component.rows = this.rows
        if (this.changeListener != null) this.changeListener!!()
    }
}

open class InQLTabbedPane: TabbedPane() {
    init {
        tabbedPane.apply {
            // Add "Settings" button on the right end
            trailingComponent = BorderPanel(3, 0, 0, 0).apply {
                add(SettingsTabButton())
            }
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

/*
    Simple SVG Color Filter that makes SVG the specified color on Dark mode
 */
class DarkModeFilter(darkModeColor: Color): ColorFilter() {
    init {
        this.setMapper { color -> if (Burp.isDarkMode()) return@setMapper darkModeColor else color }
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
            try {
                it.colorFilter = DarkModeFilter(Color.LIGHT_GRAY)
            } catch (e: Throwable) {
                Logger.info("InQL: Dark mode icon filtering not supported in this Burp version.")
            }
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
}

fun JSplitPane.applyEqualSplit(initialRatio: Double = 0.5) {
    resizeWeight = initialRatio
    getLeftComponent()?.minimumSize = Dimension(0, 0)
    getRightComponent()?.minimumSize = Dimension(0, 0)
    var initialized = false
    addComponentListener(object : java.awt.event.ComponentAdapter() {
        override fun componentResized(e: java.awt.event.ComponentEvent?) {
            if (initialized) return
            val size = if (orientation == JSplitPane.HORIZONTAL_SPLIT) width else height
            if (size <= 0) return
            dividerLocation = (size * initialRatio).toInt()
            initialized = true
        }
    })
}

class ErrorDialog(val msg: String, logToError: Boolean = true) {
    init {
        if (logToError) Logger.error(msg)
        val show = Runnable {
            val burpWindow = Burp.Montoya.userInterface().swingUtils().suiteFrame()
            JOptionPane.showMessageDialog(burpWindow, msg, "InQL Error", JOptionPane.ERROR_MESSAGE)
        }
        if (SwingUtilities.isEventDispatchThread()) {
            show.run()
        } else {
            try {
                SwingUtilities.invokeAndWait(show)
            } catch (e: Exception) {
                Logger.error("Failed to show error dialog: ${e.message}")
            }
        }
    }
}
