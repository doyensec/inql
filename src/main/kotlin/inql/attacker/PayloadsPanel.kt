package inql.attacker

import burp.api.montoya.http.message.requests.HttpRequest
import inql.ui.BorderPanel
import inql.ui.ComboBox
import inql.ui.ErrorDialog
import inql.ui.Label
import inql.ui.MultilineLabel
import inql.ui.SimpleDocumentListener
import inql.ui.committedInt
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.io.File
import java.io.IOException
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.ButtonGroup
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SpinnerNumberModel
import javax.swing.border.EmptyBorder

class PayloadsPanel : BorderPanel(4) {
    private val aliasRadio = JRadioButton(BatchMode.ALIAS.label, true)
    private val arrayRadio = JRadioButton(BatchMode.ARRAY.label, false)
    private val attackTypeCombo = ComboBox(
        "Attack type",
        *IntruderAttackType.entries.map { it.label }.toTypedArray(),
    )
    private val attackTypeDescription = MultilineLabel("").also {
        it.border = EmptyBorder(0, 4, 0, 4)
        it.alignmentX = Component.LEFT_ALIGNMENT
    }
    private val refreshButton = JButton("Refresh")
    private val batchSizeSpinner = JSpinner(
        SpinnerNumberModel(0, 0, BatchRequestBuilder.MAX_ITEMS_PER_REQUEST, 1),
    ).also {
        it.preferredSize = Dimension(90, it.preferredSize.height)
        it.toolTipText = "Split the attack into several HTTP requests with at most this many batched items each. " +
            "0 sends all items in a single request."
    }
    private val payloadSetCombo = JComboBox<PayloadSetItem>()
    private val payloadSetRow = payloadFormRow("Payload set:", payloadSetCombo).also {
        it.border = EmptyBorder(4, 4, 0, 4)
    }
    private val payloadCountLabel = JLabel("Payload count: 0")
    private val requestCountLabel = JLabel("Items: 0")
    private val httpRequestCountLabel = JLabel("HTTP requests: 0")
    private val sharedPayloadEditor = PayloadSourceEditor().also { editor ->
        editor.onChanged = {
            updateCounts()
            refreshPayloadPanelSize()
        }
    }
    private val sharedPayloadPanel = JPanel(BorderLayout()).also {
        it.border = BorderFactory.createTitledBorder("Payloads")
        it.add(payloadSetRow, BorderLayout.NORTH)
        it.add(sharedPayloadEditor, BorderLayout.CENTER)
        it.add(
            JPanel(FlowLayout(FlowLayout.LEFT, 12, 2)).also { counts ->
                counts.add(payloadCountLabel)
                counts.add(requestCountLabel)
                counts.add(httpRequestCountLabel)
            },
            BorderLayout.SOUTH,
        )
    }
    private val variablesContainer = JPanel().also {
        it.layout = BoxLayout(it, BoxLayout.Y_AXIS)
    }
    private val emptyLabel = MultilineLabel(EMPTY_MESSAGE).also {
        it.border = EmptyBorder(0, 4, 0, 4)
        it.alignmentX = Component.LEFT_ALIGNMENT
    }
    private val variableRows = mutableListOf<VariableRow>()
    /** Saved payload sets: one per variable, plus [SHARED_PAYLOAD_SET] for Sniper / Battering ram. */
    private val payloadSetSnapshots = linkedMapOf<String, PayloadSourceEditor.Snapshot>()

    /** The payload set currently shown in the editor; its snapshot is updated before switching away. */
    private var currentPayloadSetKey: String? = null
    private var rebuildingVariableRows = false
    private var suppressPayloadSetListener = false
    private var lastRefreshError: String? = null

    var onRefreshRequested: (() -> Unit)? = null

    init {
        ButtonGroup().also { group ->
            group.add(aliasRadio)
            group.add(arrayRadio)
        }
        refreshButton.addActionListener { onRefreshRequested?.invoke() }
        attackTypeCombo.addItemListener { updatePayloadVisibility() }
        batchSizeSpinner.addChangeListener { updateCounts() }
        payloadSetCombo.addItemListener {
            if (suppressPayloadSetListener) return@addItemListener
            switchPayloadSet()
        }

        val modeRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).also {
            it.add(aliasRadio)
            it.add(arrayRadio)
        }
        val optionsRow = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0)).also {
            it.add(attackTypeCombo)
            it.add(Box.createHorizontalStrut(8))
            it.add(JLabel("Items per request (0 = all):"))
            it.add(batchSizeSpinner)
        }

        val variablesScroll = JScrollPane(variablesContainer).also {
            it.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            it.horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            it.preferredSize = Dimension(0, 160)
            it.border = EmptyBorder(2, 2, 2, 2)
        }
        val variablesHeader = JPanel(BorderLayout()).also {
            it.add(refreshButton, BorderLayout.EAST)
        }
        val variablesPanel = JPanel(BorderLayout()).also {
            it.border = BorderFactory.createTitledBorder("Variables / arguments")
            it.add(variablesHeader, BorderLayout.NORTH)
            it.add(variablesScroll, BorderLayout.CENTER)
        }

        val content = JPanel().also { panel ->
            panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
            panel.add(modeRow.leftAligned())
            panel.add(optionsRow.leftAligned())
            panel.add(attackTypeDescription.leftAligned(lockHeight = false))
            panel.add(Box.createVerticalStrut(4))
            panel.add(sharedPayloadPanel.leftAligned(lockHeight = false))
            panel.add(Box.createVerticalStrut(4))
            panel.add(variablesPanel.leftAligned(lockHeight = false))
        }

        add(content, BorderLayout.CENTER)
        showEmpty(EMPTY_MESSAGE)
        updatePayloadVisibility()
    }

    fun refreshFromRequest(request: HttpRequest) {
        val previousSelected = variableRows.filter { it.isSelected() }.map { it.variable.key }.toSet()

        val result = BatchVariableCollector.collect(request)
        lastRefreshError = result.error
        variableRows.clear()
        variablesContainer.removeAll()

        if (result.variables.isEmpty()) {
            showEmpty(result.error ?: EMPTY_MESSAGE)
            updatePayloadVisibility()
            revalidate()
            repaint()
            return
        }

        emptyLabel.isVisible = false
        // Update the payload sets once at the end, not for every row added.
        rebuildingVariableRows = true
        val byKind = result.variables.groupBy { it.kind }
        for (kind in BatchVariableKind.entries) {
            val variables = byKind[kind] ?: continue
            variablesContainer.add(groupHeading(kind).leftAligned())
            for (variable in variables) {
                val row = VariableRow(variable) {
                    if (!rebuildingVariableRows) updatePayloadVisibility()
                }
                val autoSelect = result.variables.size == 1 || variable.key in previousSelected
                row.setSelected(autoSelect)
                variableRows.add(row)
                variablesContainer.add(row.leftAligned())
            }
        }
        rebuildingVariableRows = false
        updatePayloadVisibility()
        revalidate()
        repaint()
    }

    fun readConfig(): BatchAttackConfig? {
        if (variableRows.isEmpty()) {
            ErrorDialog(
                lastRefreshError ?: "No GraphQL variables or arguments found in the query.",
            )
            return null
        }
        val selected = selectedRows()
        if (selected.isEmpty()) {
            ErrorDialog("Select at least one variable to batch.")
            return null
        }

        val mode = if (arrayRadio.isSelected) BatchMode.ARRAY else BatchMode.ALIAS
        val template = BatchAttackConfig(
            mode = mode,
            attackType = selectedAttackType(),
            selectedVariables = selected.map { it.variable.key },
            sharedSource = null,
            perVariableSources = emptyMap(),
            batchSize = batchSize(),
        )

        saveCurrentPayloadSet()
        return if (template.usesSharedPayload()) {
            val snapshot = sharedPayloadEditor.snapshot()
            val source = snapshot.sourceOrShowError() ?: return null
            template.copy(sharedSource = PayloadSetConfig(source, snapshot.valueType))
        } else {
            val sources = LinkedHashMap<String, PayloadSetConfig>()
            for (row in selected) {
                val snapshot = payloadSetSnapshots[row.variable.key] ?: PayloadSourceEditor.Snapshot()
                val source = snapshot.sourceOrShowError(row.variable.displayName) ?: return null
                sources[row.variable.key] = PayloadSetConfig(source, snapshot.valueType)
            }
            template.copy(perVariableSources = sources)
        }
    }

    private fun updatePayloadVisibility() {
        val selected = selectedRows()
        val selectedCount = selected.size
        attackTypeCombo.isEnabled = selectedCount >= 2
        val usesShared = usesSharedPayload()
        payloadSetCombo.isEnabled = selectedCount > 0 && !usesShared
        rebuildPayloadSetCombo(selected, usesShared)
        attackTypeDescription.text = IntruderAttackType.fromLabel(attackTypeCombo.getSelectedItem()).description
        updateCounts()
        refreshPayloadPanelSize()
    }

    private fun rebuildPayloadSetCombo(selected: List<VariableRow>, usesShared: Boolean) {
        saveCurrentPayloadSet()
        suppressPayloadSetListener = true
        payloadSetCombo.removeAllItems()
        if (selected.isEmpty()) {
            suppressPayloadSetListener = false
            return
        }
        val items = if (usesShared) {
            val label = if (selected.size == 1) {
                selected.first().variable.displayName
            } else {
                "One payload set for each variable"
            }
            listOf(PayloadSetItem(SHARED_PAYLOAD_SET, label))
        } else {
            selected.map { PayloadSetItem(it.variable.key, it.variable.displayName) }
        }
        items.forEach { payloadSetCombo.addItem(it) }
        val keyToSelect = currentPayloadSetKey?.takeIf { key -> items.any { it.key == key } } ?: items.first().key
        payloadSetCombo.selectedIndex = items.indexOfFirst { it.key == keyToSelect }
        suppressPayloadSetListener = false
        if (keyToSelect != currentPayloadSetKey) {
            // A set that was never configured starts from what is on screen, e.g. the Sniper payloads
            // carry over to the first variable when switching to Pitchfork for the first time.
            showPayloadSet(keyToSelect, fallback = sharedPayloadEditor.snapshot())
        }
    }

    private fun switchPayloadSet() {
        if (usesSharedPayload()) return
        val item = payloadSetCombo.selectedItem as? PayloadSetItem ?: return
        if (item.key == currentPayloadSetKey) return
        saveCurrentPayloadSet()
        showPayloadSet(item.key, fallback = PayloadSourceEditor.Snapshot())
        updateCounts()
        refreshPayloadPanelSize()
    }

    private fun showPayloadSet(key: String, fallback: PayloadSourceEditor.Snapshot) {
        currentPayloadSetKey = key
        sharedPayloadEditor.restore(payloadSetSnapshots[key] ?: fallback)
        payloadSetSnapshots[key] = sharedPayloadEditor.snapshot()
    }

    private fun refreshPayloadPanelSize() {
        sharedPayloadPanel.maximumSize = Dimension(
            Integer.MAX_VALUE,
            sharedPayloadPanel.preferredSize.height.coerceAtLeast(1),
        )
        revalidate()
        repaint()
    }

    private fun saveCurrentPayloadSet() {
        val key = currentPayloadSetKey ?: return
        payloadSetSnapshots[key] = sharedPayloadEditor.snapshot()
    }

    private fun updateCounts() {
        val selected = selectedRows()
        val payloadCount = currentPayloadCount()
        val requestCount = if (selected.isEmpty()) {
            0L
        } else if (usesSharedPayload()) {
            BatchRequestBuilder.estimateItemCount(
                selectedAttackType(),
                selected.size,
                listOf(payloadCount),
            )
        } else {
            val counts = selected.map { row ->
                val snapshot = if (row.variable.key == currentPayloadSetKey) {
                    sharedPayloadEditor.snapshot()
                } else {
                    payloadSetSnapshots[row.variable.key]
                }
                PayloadSource.countOrZero(snapshot?.sourceOrNull())
            }
            BatchRequestBuilder.estimateItemCount(selectedAttackType(), selected.size, counts)
        }
        payloadCountLabel.text = "Payload count: ${BatchRequestBuilder.formatCount(payloadCount)}"
        requestCountLabel.text = "Items: ${BatchRequestBuilder.formatCount(requestCount)}"
        val httpRequests = BatchRequestBuilder.requestCount(requestCount, batchSize())
        httpRequestCountLabel.text = "HTTP requests: ${BatchRequestBuilder.formatCount(httpRequests)}"
    }

    private fun batchSize(): Int = batchSizeSpinner.committedInt()

    private fun currentPayloadCount(): Long {
        return PayloadSource.countOrZero(sharedPayloadEditor.snapshot().sourceOrNull())
    }

    private fun selectedAttackType(): IntruderAttackType {
        return IntruderAttackType.fromLabel(attackTypeCombo.getSelectedItem()).effectiveFor(selectedRows().size)
    }

    private fun usesSharedPayload(): Boolean = selectedAttackType().usesSharedPayloadSet

    private fun selectedRows(): List<VariableRow> = variableRows.filter { it.isSelected() }

    private fun showEmpty(message: String) {
        emptyLabel.text = message
        emptyLabel.isVisible = true
        variablesContainer.add(emptyLabel)
    }

    private fun groupHeading(kind: BatchVariableKind): JComponent {
        return Label(kind.groupTitle, bold = true).also {
            it.border = EmptyBorder(if (variableRows.isEmpty()) 0 else 6, 4, 2, 4)
        }
    }

    private fun JComponent.leftAligned(lockHeight: Boolean = true): JComponent {
        alignmentX = Component.LEFT_ALIGNMENT
        maximumSize = Dimension(
            Integer.MAX_VALUE,
            if (lockHeight) preferredSize.height.coerceAtLeast(1) else Integer.MAX_VALUE,
        )
        return this
    }

    private data class PayloadSetItem(val key: String, val label: String) {
        override fun toString(): String = label
    }

    companion object {
        /** Key of the payload set used by Sniper / Battering ram; variable keys are never empty. */
        private const val SHARED_PAYLOAD_SET = ""

        private const val EMPTY_MESSAGE = "No GraphQL variables or arguments found in the request."
    }
}

private class VariableRow(
    val variable: BatchVariable,
    private val onSelectionChanged: () -> Unit,
) : JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)) {
    private val checkbox = JCheckBox(labelFor(variable)).also {
        it.addItemListener { onSelectionChanged() }
    }

    init {
        add(checkbox)
        alignmentX = Component.LEFT_ALIGNMENT
    }

    fun isSelected(): Boolean = checkbox.isSelected

    fun setSelected(selected: Boolean) {
        checkbox.isSelected = selected
    }

    companion object {
        /** The name under its group heading, indented by nesting depth. */
        private fun labelFor(variable: BatchVariable): String {
            // An argument path starts with its field and argument name, a variable path with the variable name.
            val topLevelSegments = if (variable.kind == BatchVariableKind.ARGUMENT) 2 else 1
            val indent = "    ".repeat((variable.path.size - topLevelSegments).coerceAtLeast(0))
            return if (variable.type.isNullOrBlank()) {
                indent + variable.name
            } else {
                "$indent${variable.name}  (${variable.type})"
            }
        }
    }
}

private enum class PayloadKind(val label: String) {
    FILE("File"),
    NUMBERS("Numbers"),
    BRUTE_FORCE("Brute forcer"),
    SIMPLE_LIST("Simple list"),
    NULL("Null"),
    ;

    override fun toString(): String = label
}

private class PayloadSourceEditor : JPanel() {
    /** Everything the editor shows; the defaults are what a new payload set starts with. */
    data class Snapshot(
        val kind: PayloadKind = PayloadKind.SIMPLE_LIST,
        val path: String = "",
        val from: Int = 0,
        val to: Int = 9,
        val minDigits: Int = 0,
        val charset: String = "0123456789",
        val minLen: Int = 1,
        val maxLen: Int = 3,
        val words: List<String> = emptyList(),
        val nullCount: Int = 10,
        val valueType: PayloadValueType = PayloadValueType.AUTO,
    ) {
        /** Why these settings do not describe a usable payload source yet, or null if they do. */
        fun problem(): String? = when (kind) {
            PayloadKind.FILE -> "Choose a payload file".takeIf { path.isBlank() }
            PayloadKind.NUMBERS -> "Number range From ($from) is greater than To ($to)".takeIf { from > to }
            PayloadKind.BRUTE_FORCE -> when {
                charset.isEmpty() -> "Enter a brute force character set"
                maxLen < minLen -> "Brute force Max is smaller than Min"
                else -> null
            }
            PayloadKind.SIMPLE_LIST -> "Add at least one item to the list".takeIf { PayloadSource.words(words).isEmpty() }
            PayloadKind.NULL -> null
        }

        fun sourceOrNull(): PayloadSource? {
            if (problem() != null) return null
            return when (kind) {
                PayloadKind.FILE -> PayloadSource.FilePath(path.trim())
                PayloadKind.NUMBERS -> PayloadSource.NumberRange(from, to, minDigits)
                PayloadKind.BRUTE_FORCE -> PayloadSource.BruteForce(charset, minLen, maxLen)
                PayloadKind.SIMPLE_LIST -> PayloadSource.WordList(words)
                PayloadKind.NULL -> PayloadSource.NullPayloads(nullCount)
            }
        }

        /** Like [sourceOrNull], but tells the user what is missing. */
        fun sourceOrShowError(variableLabel: String? = null): PayloadSource? {
            problem()?.let { problem ->
                ErrorDialog(problem + (variableLabel?.let { " for $it" } ?: "") + ".")
                return null
            }
            return sourceOrNull()
        }
    }

    var onChanged: (() -> Unit)? = null

    private val kindCombo = JComboBox(PayloadKind.entries.toTypedArray())
    private val valueTypeCombo = JComboBox(PayloadValueType.entries.map { it.label }.toTypedArray()).also {
        it.toolTipText = "JSON type the payloads are sent as. Auto follows the variable's type. " +
            "Payloads that are not valid values of the chosen type stop the attack."
    }
    private val pathField = JTextField(18).also { it.isEditable = false }
    private val browseButton = JButton("Browse…")
    private val fromSpinner = JSpinner(SpinnerNumberModel(0, Integer.MIN_VALUE, Integer.MAX_VALUE, 1))
    private val toSpinner = JSpinner(SpinnerNumberModel(0, Integer.MIN_VALUE, Integer.MAX_VALUE, 1))
    private val minDigitsSpinner = JSpinner(SpinnerNumberModel(0, 0, 18, 1)).also {
        it.toolTipText = "Pad numbers with leading zeros to at least this many digits (0 = no padding)."
    }
    private val charsetField = JTextField(16)
    private val minLenSpinner = JSpinner(SpinnerNumberModel(0, 0, 16, 1))
    private val maxLenSpinner = JSpinner(SpinnerNumberModel(0, 0, 16, 1))
    private val listModel = DefaultListModel<String>()
    private val list = JList(listModel).also {
        it.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
    }
    private val addField = JTextField()
    private val addButton = JButton("Add")
    private val pasteButton = JButton("Paste")
    private val loadListButton = JButton("Load")
    private val removeButton = JButton("Remove")
    private val clearButton = JButton("Clear")
    private val dedupeButton = JButton("Deduplicate")
    private val nullCountSpinner = JSpinner(SpinnerNumberModel(1, 1, PayloadSource.MAX_GENERATED, 1))

    private val fileRow = payloadFormRow("File:", pathField, browseButton)
    private val numbersRow = payloadFormRow(
        "From:",
        fromSpinner,
        JLabel("To:"),
        toSpinner,
        JLabel("Min digits:"),
        minDigitsSpinner,
    )
    private val bruteRow = payloadFormRow(
        "Charset:",
        charsetField,
        JLabel("Min:"),
        minLenSpinner,
        JLabel("Max:"),
        maxLenSpinner,
    )
    private val listRow = JPanel(BorderLayout(6, 4)).also { panel ->
        val buttons = stackedButtons(pasteButton, loadListButton, removeButton, clearButton, dedupeButton)
        val addRow = payloadFormRow("Add:", addField, addButton)
        val listHeight = buttons.preferredSize.height.coerceAtLeast(1)
        val listScroll = JScrollPane(list).also {
            it.preferredSize = Dimension(200, listHeight)
            it.minimumSize = Dimension(120, listHeight)
        }
        panel.add(listScroll, BorderLayout.CENTER)
        panel.add(buttons, BorderLayout.EAST)
        panel.add(addRow, BorderLayout.SOUTH)
        val totalHeight = listHeight + addRow.preferredSize.height + 8
        panel.minimumSize = Dimension(180, totalHeight)
        panel.preferredSize = Dimension(280, totalHeight)
        panel.alignmentX = Component.LEFT_ALIGNMENT
    }
    private val nullRow = payloadFormRow("Count:", nullCountSpinner)
    private val valueTypeRow = payloadFormRow("Send as:", valueTypeCombo)

    /**
     * Shows the settings of the selected payload type. CardLayout reserves the height of the tallest type
     * (Simple list), so switching types never resizes the panel; shorter rows stay pinned to the top.
     */
    private val kindCards = JPanel(CardLayout()).also { cards ->
        val rows = mapOf(
            PayloadKind.FILE to fileRow,
            PayloadKind.NUMBERS to numbersRow,
            PayloadKind.BRUTE_FORCE to bruteRow,
            PayloadKind.SIMPLE_LIST to listRow,
            PayloadKind.NULL to nullRow,
        )
        for ((kind, row) in rows) {
            cards.add(JPanel(BorderLayout()).also { it.add(row, BorderLayout.NORTH) }, kind.name)
        }
        cards.alignmentX = Component.LEFT_ALIGNMENT
        cards.maximumSize = Dimension(Integer.MAX_VALUE, cards.preferredSize.height)
    }

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = Component.LEFT_ALIGNMENT
        border = EmptyBorder(0, 4, 0, 4)
        browseButton.addActionListener { choosePayloadFile() }
        kindCombo.addActionListener { updateKindVisibility() }
        addButton.addActionListener { addListItem() }
        addField.addActionListener { addListItem() }
        pasteButton.addActionListener { pasteListItems() }
        loadListButton.addActionListener { loadListItems() }
        removeButton.addActionListener { removeListItems() }
        clearButton.addActionListener {
            listModel.clear()
            notifyChanged()
        }
        dedupeButton.addActionListener { deduplicateListItems() }
        valueTypeCombo.addActionListener { notifyChanged() }
        val kindRow = payloadFormRow("Payload type:", kindCombo)
        listOf(fromSpinner, toSpinner, minDigitsSpinner, minLenSpinner, maxLenSpinner, nullCountSpinner).forEach { spinner ->
            spinner.preferredSize = Dimension(80, spinner.preferredSize.height)
            spinner.addChangeListener { notifyChanged() }
        }
        charsetField.document.addDocumentListener(SimpleDocumentListener { notifyChanged() })
        add(kindRow)
        add(valueTypeRow)
        add(kindCards)
        restore(Snapshot())
    }

    fun snapshot(): Snapshot {
        return Snapshot(
            kind = kindCombo.selectedItem as PayloadKind,
            path = pathField.text,
            from = fromSpinner.committedInt(),
            to = toSpinner.committedInt(),
            minDigits = minDigitsSpinner.committedInt(),
            charset = charsetField.text,
            minLen = minLenSpinner.committedInt(),
            maxLen = maxLenSpinner.committedInt(),
            words = listWords(),
            nullCount = nullCountSpinner.committedInt(),
            valueType = PayloadValueType.entries[valueTypeCombo.selectedIndex],
        )
    }

    fun restore(snapshot: Snapshot) {
        kindCombo.selectedItem = snapshot.kind
        pathField.text = snapshot.path
        fromSpinner.value = snapshot.from
        toSpinner.value = snapshot.to
        minDigitsSpinner.value = snapshot.minDigits
        charsetField.text = snapshot.charset
        minLenSpinner.value = snapshot.minLen
        maxLenSpinner.value = snapshot.maxLen
        listModel.clear()
        snapshot.words.forEach { listModel.addElement(it) }
        nullCountSpinner.value = snapshot.nullCount
        valueTypeCombo.selectedIndex = snapshot.valueType.ordinal
        updateKindVisibility()
    }

    private fun addListItem() {
        val value = addField.text.trimEnd()
        if (value.isEmpty()) return
        listModel.addElement(value)
        addField.text = ""
        addField.requestFocusInWindow()
        notifyChanged()
    }

    private fun pasteListItems() {
        val text = try {
            Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as? String
        } catch (_: Exception) {
            null
        }
        if (!text.isNullOrEmpty()) addListLines(text.lines())
    }

    private fun loadListItems() {
        val file = chooseFile() ?: return
        val lines = try {
            file.readLines()
        } catch (e: IOException) {
            ErrorDialog("Failed to read ${file.absolutePath}: ${e.message}")
            return
        }
        addListLines(lines)
    }

    private fun addListLines(lines: List<String>) {
        val words = PayloadSource.words(lines)
        if (words.isEmpty()) return
        words.forEach { listModel.addElement(it) }
        notifyChanged()
    }

    private fun removeListItems() {
        val indices = list.selectedIndices.sortedDescending()
        if (indices.isEmpty()) return
        indices.forEach { listModel.remove(it) }
        notifyChanged()
    }

    private fun deduplicateListItems() {
        val unique = listWords().distinct()
        if (unique.size == listModel.size()) return
        listModel.clear()
        unique.forEach { listModel.addElement(it) }
        notifyChanged()
    }

    private fun choosePayloadFile() {
        val file = chooseFile(pathField.text.trim().takeIf { it.isNotEmpty() }?.let { File(it) }) ?: return
        pathField.text = file.absolutePath
        notifyChanged()
    }

    /** Asks for a file, starting next to [current] if given, otherwise in the home directory. */
    private fun chooseFile(current: File? = null): File? {
        val chooser = JFileChooser().also {
            it.currentDirectory = current?.parentFile?.takeIf { dir -> dir.isDirectory }
                ?: File(System.getProperty("user.home"))
            if (current?.isFile == true) it.selectedFile = current
        }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return null
        return chooser.selectedFile
    }

    private fun updateKindVisibility() {
        val kind = kindCombo.selectedItem as PayloadKind
        (kindCards.layout as CardLayout).show(kindCards, kind.name)
        // Null payloads keep the original value, so there is nothing to convert. Disabled rather than hidden
        // so the panel keeps its height.
        valueTypeCombo.isEnabled = kind != PayloadKind.NULL
        maximumSize = Dimension(Integer.MAX_VALUE, preferredSize.height.coerceAtLeast(1))
        revalidate()
        repaint()
        notifyChanged()
    }

    private fun listWords(): List<String> = (0 until listModel.size()).map { listModel.getElementAt(it) }

    private fun notifyChanged() {
        onChanged?.invoke()
    }
}

private const val PAYLOAD_LABEL_WIDTH = 96

private fun payloadFormRow(label: String, vararg components: Component): JPanel {
    val panel = JPanel(GridBagLayout())
    val labelConstraints = GridBagConstraints().apply {
        gridx = 0
        gridy = 0
        anchor = GridBagConstraints.WEST
        insets = Insets(2, 0, 2, 8)
    }
    val labelComp = JLabel(label).also {
        val size = Dimension(PAYLOAD_LABEL_WIDTH, it.preferredSize.height)
        it.preferredSize = size
        it.minimumSize = size
        it.maximumSize = size
    }
    panel.add(labelComp, labelConstraints)
    components.forEachIndexed { index, component ->
        val constraints = GridBagConstraints().apply {
            gridx = index + 1
            gridy = 0
            anchor = GridBagConstraints.WEST
            insets = Insets(2, 0, 2, 6)
            if (component is JTextField || component is JComboBox<*>) {
                fill = GridBagConstraints.HORIZONTAL
                weightx = 1.0
            }
        }
        panel.add(component, constraints)
    }
    val stretches = components.any { it is JTextField || it is JComboBox<*> }
    if (!stretches) {
        panel.add(
            Box.createHorizontalGlue(),
            GridBagConstraints().apply {
                gridx = components.size + 1
                gridy = 0
                weightx = 1.0
                fill = GridBagConstraints.HORIZONTAL
            },
        )
    }
    panel.alignmentX = Component.LEFT_ALIGNMENT
    panel.maximumSize = Dimension(Integer.MAX_VALUE, panel.preferredSize.height.coerceAtLeast(1))
    return panel
}

private fun stackedButtons(vararg buttons: JButton): JPanel {
    val width = buttons.maxOf { it.preferredSize.width }
    return JPanel().also { panel ->
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        buttons.forEach { button ->
            button.alignmentX = Component.LEFT_ALIGNMENT
            val height = button.preferredSize.height
            button.preferredSize = Dimension(width, height)
            button.maximumSize = Dimension(Integer.MAX_VALUE, height)
            panel.add(button)
            panel.add(Box.createVerticalStrut(2))
        }
    }
}
