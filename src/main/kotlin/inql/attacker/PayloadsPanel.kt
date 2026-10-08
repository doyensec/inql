package inql.attacker

import burp.api.montoya.http.message.requests.HttpRequest
import inql.ui.BorderPanel
import inql.ui.ComboBox
import inql.ui.ErrorDialog
import inql.ui.MultilineLabel
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
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

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

        val result = try {
            BatchVariableCollector.collect(request)
        } catch (e: Exception) {
            VariableCollectResult(
                variables = emptyList(),
                payload = null,
                error = "Failed to read GraphQL variables: ${e.message}",
            )
        }
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
        for (variable in result.variables) {
            val row = VariableRow(variable) {
                if (!rebuildingVariableRows) updatePayloadVisibility()
            }
            val autoSelect = result.variables.size == 1 || variable.key in previousSelected
            row.setSelected(autoSelect)
            variableRows.add(row)
            variablesContainer.add(row.leftAligned())
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
        val attackType = if (selected.size < 2) {
            IntruderAttackType.SNIPER
        } else {
            IntruderAttackType.fromLabel(attackTypeCombo.getSelectedItem())
        }
        val template = BatchAttackConfig(
            mode = mode,
            attackType = attackType,
            selectedVariables = selected.map { it.variable.key },
            sharedSource = null,
            perVariableSources = emptyMap(),
            batchSize = batchSize(),
        )

        saveCurrentPayloadSet()
        return if (template.usesSharedPayload()) {
            val snapshot = sharedPayloadEditor.snapshot()
            val source = PayloadSourceEditor.sourceFrom(snapshot) ?: return null
            template.copy(sharedSource = PayloadSetConfig(source, PayloadValueType.fromIndex(snapshot.valueTypeIndex)))
        } else {
            val sources = LinkedHashMap<String, PayloadSetConfig>()
            for (row in selected) {
                val snapshot = payloadSetSnapshots[row.variable.key] ?: defaultPayloadSnapshot()
                val source = PayloadSourceEditor.sourceFrom(snapshot, row.variable.displayName) ?: return null
                sources[row.variable.key] = PayloadSetConfig(source, PayloadValueType.fromIndex(snapshot.valueTypeIndex))
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
        showPayloadSet(item.key, fallback = defaultPayloadSnapshot())
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
                snapshot?.let { PayloadSource.countOrZero(PayloadSourceEditor.peekFrom(it)) } ?: 0L
            }
            BatchRequestBuilder.estimateItemCount(selectedAttackType(), selected.size, counts)
        }
        payloadCountLabel.text = "Payload count: ${formatCount(payloadCount)}"
        requestCountLabel.text = "Items: ${formatCount(requestCount)}"
        val httpRequests = BatchRequestBuilder.requestCount(requestCount, batchSize())
        httpRequestCountLabel.text = "HTTP requests: ${formatCount(httpRequests)}"
    }

    private fun batchSize(): Int {
        try {
            batchSizeSpinner.commitEdit()
        } catch (_: java.text.ParseException) {
            // Keep last valid value.
        }
        return batchSizeSpinner.value as Int
    }

    private fun currentPayloadCount(): Long {
        return PayloadSource.countOrZero(sharedPayloadEditor.peekSource())
    }

    private fun selectedAttackType(): IntruderAttackType {
        val selectedCount = variableRows.count { it.isSelected() }
        return if (selectedCount < 2) {
            IntruderAttackType.SNIPER
        } else {
            IntruderAttackType.fromLabel(attackTypeCombo.getSelectedItem())
        }
    }

    private fun usesSharedPayload(): Boolean {
        val selectedCount = variableRows.count { it.isSelected() }
        return selectedCount < 2 ||
            selectedAttackType() == IntruderAttackType.SNIPER ||
            selectedAttackType() == IntruderAttackType.BATTERING_RAM
    }

    private fun selectedRows(): List<VariableRow> = variableRows.filter { it.isSelected() }

    private fun formatCount(value: Long): String {
        return if (value == Long.MAX_VALUE) "too large" else value.toString()
    }

    private fun showEmpty(message: String) {
        emptyLabel.text = message
        emptyLabel.isVisible = true
        variablesContainer.add(emptyLabel)
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

        private fun defaultPayloadSnapshot(): PayloadSourceEditor.Snapshot {
            return PayloadSourceEditor.Snapshot(
                kindIndex = PayloadSourceEditor.DEFAULT_KIND_INDEX,
                path = "",
                from = 0,
                to = 9,
                charset = "0123456789",
                minLen = 1,
                maxLen = 3,
                words = "",
                nullCount = 10,
            )
        }
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
        private fun labelFor(variable: BatchVariable): String {
            val indent = "    ".repeat((variable.path.size - 1).coerceAtLeast(0))
            return if (variable.type.isNullOrBlank()) {
                indent + variable.displayName
            } else {
                "$indent${variable.displayName}  (${variable.type})"
            }
        }
    }
}

private class PayloadSourceEditor : JPanel() {
    data class Snapshot(
        val kindIndex: Int,
        val path: String,
        val from: Int,
        val to: Int,
        val charset: String,
        val minLen: Int,
        val maxLen: Int,
        val words: String,
        val nullCount: Int,
        val minDigits: Int = 0,
        val valueTypeIndex: Int = 0,
    )

    var onChanged: (() -> Unit)? = null

    private val kindCombo = JComboBox(
        arrayOf("File", "Numbers", "Brute forcer", "Simple list", "Null"),
    ).also { it.selectedIndex = DEFAULT_KIND_INDEX }
    private val valueTypeCombo = JComboBox(PayloadValueType.entries.map { it.label }.toTypedArray()).also {
        it.toolTipText = "JSON type the payloads are sent as. Auto follows the variable's type. " +
            "Payloads that are not valid values of the chosen type stop the attack."
    }
    private val pathField = JTextField(18).also { it.isEditable = false }
    private val browseButton = JButton("Browse…")
    private val fromSpinner = JSpinner(SpinnerNumberModel(0, Integer.MIN_VALUE, Integer.MAX_VALUE, 1))
    private val toSpinner = JSpinner(SpinnerNumberModel(9, Integer.MIN_VALUE, Integer.MAX_VALUE, 1))
    private val minDigitsSpinner = JSpinner(SpinnerNumberModel(0, 0, 18, 1)).also {
        it.toolTipText = "Pad numbers with leading zeros to at least this many digits (0 = no padding)."
    }
    private val charsetField = JTextField("0123456789", 16)
    private val minLenSpinner = JSpinner(SpinnerNumberModel(1, 0, 16, 1))
    private val maxLenSpinner = JSpinner(SpinnerNumberModel(3, 0, 16, 1))
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
    private val nullCountSpinner = JSpinner(SpinnerNumberModel(10, 1, PayloadSource.MAX_GENERATED, 1))

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
        listOf(fileRow, numbersRow, bruteRow, listRow, nullRow).forEachIndexed { index, row ->
            cards.add(JPanel(BorderLayout()).also { it.add(row, BorderLayout.NORTH) }, index.toString())
        }
        cards.alignmentX = Component.LEFT_ALIGNMENT
        cards.maximumSize = Dimension(Integer.MAX_VALUE, cards.preferredSize.height)
    }

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = Component.LEFT_ALIGNMENT
        border = EmptyBorder(0, 4, 0, 4)
        browseButton.addActionListener { chooseFile() }
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
        add(valueTypeRow.leftGrow())
        add(kindCards)
        updateKindVisibility()
    }

    fun peekSource(): PayloadSource? = peekFrom(snapshot())

    fun snapshot(): Snapshot {
        return Snapshot(
            kindIndex = kindCombo.selectedIndex,
            path = pathField.text,
            from = commitSpinner(fromSpinner),
            to = commitSpinner(toSpinner),
            charset = charsetField.text,
            minLen = commitSpinner(minLenSpinner),
            maxLen = commitSpinner(maxLenSpinner),
            words = listWords().joinToString("\n"),
            nullCount = commitSpinner(nullCountSpinner),
            minDigits = commitSpinner(minDigitsSpinner),
            valueTypeIndex = valueTypeCombo.selectedIndex,
        )
    }

    fun restore(snapshot: Snapshot) {
        kindCombo.selectedIndex = snapshot.kindIndex.coerceIn(0, kindCombo.itemCount - 1)
        pathField.text = snapshot.path
        fromSpinner.value = snapshot.from
        toSpinner.value = snapshot.to
        charsetField.text = snapshot.charset
        minLenSpinner.value = snapshot.minLen
        maxLenSpinner.value = snapshot.maxLen
        listModel.clear()
        snapshot.words.split('\n').filter { it.isNotEmpty() }.forEach { listModel.addElement(it) }
        nullCountSpinner.value = snapshot.nullCount
        minDigitsSpinner.value = snapshot.minDigits
        valueTypeCombo.selectedIndex = PayloadValueType.fromIndex(snapshot.valueTypeIndex).ordinal
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
        if (text.isNullOrEmpty()) return
        var added = false
        text.split('\n').map { it.trimEnd() }.filter { it.isNotEmpty() }.forEach {
            listModel.addElement(it)
            added = true
        }
        if (added) notifyChanged()
    }

    private fun loadListItems() {
        val chooser = JFileChooser().also {
            it.currentDirectory = File(System.getProperty("user.home"))
        }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        var added = false
        chooser.selectedFile.bufferedReader().use { reader ->
            reader.lineSequence().forEach { line ->
                val value = line.trimEnd()
                if (value.isNotEmpty()) {
                    listModel.addElement(value)
                    added = true
                }
            }
        }
        if (added) notifyChanged()
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

    private fun chooseFile() {
        val chooser = JFileChooser().also {
            it.currentDirectory = File(System.getProperty("user.home"))
            val current = pathField.text.trim()
            if (current.isNotEmpty()) {
                val file = File(current)
                if (file.parentFile?.isDirectory == true) {
                    it.currentDirectory = file.parentFile
                }
                if (file.isFile) it.selectedFile = file
            }
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            pathField.text = chooser.selectedFile.absolutePath
            notifyChanged()
        }
    }

    private fun updateKindVisibility() {
        val index = kindCombo.selectedIndex
        (kindCards.layout as CardLayout).show(kindCards, index.toString())
        // Null payloads keep the original value, so there is nothing to convert. Disabled rather than hidden
        // so the panel keeps its height.
        valueTypeCombo.isEnabled = index != 4
        maximumSize = Dimension(Integer.MAX_VALUE, preferredSize.height.coerceAtLeast(1))
        revalidate()
        repaint()
        notifyChanged()
    }

    private fun listWords(): List<String> = (0 until listModel.size()).map { listModel.getElementAt(it) }

    private fun notifyChanged() {
        onChanged?.invoke()
    }

    private fun commitSpinner(spinner: JSpinner): Int {
        try {
            spinner.commitEdit()
        } catch (_: java.text.ParseException) {
            // Keep last valid value.
        }
        return spinner.value as Int
    }

    private fun JComponent.leftGrow(): JComponent {
        alignmentX = Component.LEFT_ALIGNMENT
        return this
    }

    companion object {
        const val DEFAULT_KIND_INDEX = 3 // Simple list

        fun sourceFrom(snapshot: Snapshot, variableLabel: String? = null): PayloadSource? {
            val prefix = variableLabel?.let { " for $it" } ?: ""
            return when (snapshot.kindIndex) {
                0 -> {
                    val path = snapshot.path.trim()
                    if (path.isEmpty()) {
                        ErrorDialog("Choose a payload file$prefix.")
                        null
                    } else {
                        PayloadSource.FilePath(path)
                    }
                }
                1 -> {
                    if (snapshot.from > snapshot.to) {
                        ErrorDialog("Number range From (${snapshot.from}) is greater than To (${snapshot.to})$prefix.")
                        null
                    } else {
                        PayloadSource.NumberRange(snapshot.from, snapshot.to, snapshot.minDigits)
                    }
                }
                2 -> {
                    if (snapshot.charset.isEmpty()) {
                        ErrorDialog("Enter a brute force character set$prefix.")
                        null
                    } else if (snapshot.maxLen < snapshot.minLen) {
                        ErrorDialog("Brute force Max is smaller than Min$prefix.")
                        null
                    } else {
                        PayloadSource.BruteForce(snapshot.charset, snapshot.minLen, snapshot.maxLen)
                    }
                }
                3 -> {
                    val words = snapshot.words.split('\n')
                    if (words.none { it.isNotBlank() }) {
                        ErrorDialog("Add at least one item to the list$prefix.")
                        null
                    } else {
                        PayloadSource.WordList(words)
                    }
                }
                else -> PayloadSource.NullPayloads(snapshot.nullCount)
            }
        }

        fun peekFrom(snapshot: Snapshot): PayloadSource? {
            return when (snapshot.kindIndex) {
                0 -> snapshot.path.trim().takeIf { it.isNotEmpty() }?.let { PayloadSource.FilePath(it) }
                1 -> if (snapshot.from > snapshot.to) {
                    null
                } else {
                    PayloadSource.NumberRange(snapshot.from, snapshot.to, snapshot.minDigits)
                }
                2 -> if (snapshot.charset.isEmpty() || snapshot.maxLen < snapshot.minLen) {
                    null
                } else {
                    PayloadSource.BruteForce(snapshot.charset, snapshot.minLen, snapshot.maxLen)
                }
                3 -> {
                    val words = snapshot.words.split('\n').filter { it.isNotEmpty() }
                    if (words.isEmpty()) null else PayloadSource.WordList(words)
                }
                else -> PayloadSource.NullPayloads(snapshot.nullCount)
            }
        }
    }
}

internal class SimpleDocumentListener(val callback: () -> Unit) : DocumentListener {
    override fun insertUpdate(e: DocumentEvent?) = callback()
    override fun removeUpdate(e: DocumentEvent?) = callback()
    override fun changedUpdate(e: DocumentEvent?) = callback()
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
