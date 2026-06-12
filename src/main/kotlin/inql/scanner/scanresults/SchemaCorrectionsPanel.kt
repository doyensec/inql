package inql.scanner.scanresults

import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInterfaceType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLSchema
import inql.schema.corrections.GraphQLErrorPathParser
import inql.schema.corrections.SchemaCorrections
import inql.schema.corrections.SchemaPathWalker
import inql.schema.corrections.SchemaTypeCatalog
import inql.scanner.ScanResult
import inql.ui.BorderPanel
import inql.ui.GraphQLEditor
import inql.utils.GraphQLEditorSearchPanel
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridLayout
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.BorderFactory
import javax.swing.DefaultComboBoxModel
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.event.ListSelectionListener

class SchemaCorrectionsPanel(
    private val view: ScanResultsView,
    private var scanResult: ScanResult,
) : BorderPanel(8) {
    companion object {
        private const val FORM_LABEL_WIDTH = 220
        private const val INPUT_ENUM_COMBO_WIDTH = 280
        private const val MAX_PATH_DEPTH = 8
        private val ENUM_KIND_STANDALONE = "Standalone enum type"
        private val ENUM_KIND_INPUT_FIELD = "Input object field"
    }
    private val statusLabel = JLabel(" ")
    private val renameOldCombo = JComboBox<String>()
    private val renameNewCombo = JComboBox<String>()
    private val schemaTypesScroll = JScrollPane()
    private val schemaTypesListModel = DefaultListModel<String>()
    private val schemaTypesList = JList(schemaTypesListModel)
    private val renameListModel = DefaultListModel<String>()
    private val renameList = JList(renameListModel)
    private val enumKindCombo = JComboBox(arrayOf(ENUM_KIND_STANDALONE, ENUM_KIND_INPUT_FIELD))
    private val enumTypeCombo = JComboBox<String>()
    private val enumInputRootCombo = JComboBox<String>()
    private val enumValuesField = JTextField(32)
    private val enumValuesListModel = DefaultListModel<String>()
    private val enumValuesList = JList(enumValuesListModel)
    private val enumInputPathPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
    private val enumInputPathSegmentCombos = mutableListOf<JComboBox<String>>()
    private val enumInputPathResolvedLabel = JLabel(" ")
    private val argumentPathRootCombo = JComboBox<String>()
    private val argumentPathPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
    private val argumentPathSegmentCombos = mutableListOf<JComboBox<String>>()
    private val argumentPathResolvedLabel = JLabel(" ")
    private val argumentParentTypeManualPanel = JPanel()
    private val argumentParentTypeCombo = JComboBox<String>()
    private val argumentFieldCombo = JComboBox<String>()
    private val argumentNameCombo = JComboBox<String>()
    private val argumentTypeCombo = JComboBox<String>()
    private val argumentTypeListModel = DefaultListModel<String>()
    private val argumentTypeList = JList(argumentTypeListModel)
    private val enumStandaloneTargetPanel = JPanel()
    private val enumInputTargetPanel = JPanel()
    private val correctionsTabs = JTabbedPane()
    private val sdlEditor = GraphQLEditor(readOnly = false, isIntrospection = true)
    private var workingCorrections: SchemaCorrections = scanResult.schemaCorrections
    private var typeCatalog: SchemaTypeCatalog.Catalog = SchemaTypeCatalog.fromScanResult(scanResult)

    init {
        border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        renameOldCombo.isEditable = true
        renameNewCombo.isEditable = true
        enumTypeCombo.isEditable = true
        enumInputRootCombo.isEditable = true
        argumentPathRootCombo.isEditable = true
        argumentParentTypeCombo.isEditable = true
        argumentFieldCombo.isEditable = true
        argumentNameCombo.isEditable = true
        argumentTypeCombo.isEditable = true
        applyInputEnumComboWidth(enumTypeCombo)
        applyInputEnumComboWidth(enumInputRootCombo)
        applyInputEnumComboWidth(argumentPathRootCombo)
        applyInputEnumComboWidth(argumentParentTypeCombo)
        applyInputEnumComboWidth(argumentFieldCombo)
        applyInputEnumComboWidth(argumentNameCombo)
        applyInputEnumComboWidth(argumentTypeCombo)

        schemaTypesList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        schemaTypesList.cellRenderer = SchemaTypeListCellRenderer()
        schemaTypesScroll.viewport.view = schemaTypesList
        schemaTypesList.addListSelectionListener(ListSelectionListener {
            val selected = schemaTypesList.selectedValue ?: return@ListSelectionListener
            if (typeCatalog.isSectionHeader(selected) || typeCatalog.isSpacer(selected)) {
                return@ListSelectionListener
            }
            selectComboValue(renameOldCombo, selected)
        })

        correctionsTabs.addTab("Type Renames", buildRenamesPanel())
        correctionsTabs.addTab("Argument Types", buildArgumentTypesPanel())
        correctionsTabs.addTab("Enum Values", buildEnumValuesPanel())
        correctionsTabs.addTab("SDL Editor", buildSdlPanel())

        val actions = JPanel(FlowLayout(FlowLayout.LEFT))
        val saveButton = JButton("Save corrections").also { it.addActionListener { saveCorrections() } }
        val revertButton = JButton("Revert corrections").also { it.addActionListener { revertCorrections() } }
        actions.add(saveButton)
        actions.add(revertButton)

        add(correctionsTabs, BorderLayout.CENTER)
        add(actions, BorderLayout.NORTH)
        add(statusLabel, BorderLayout.SOUTH)
        reloadFromScanResult()
    }

    fun load(result: ScanResult) {
        val sameResult = result.uuid == scanResult.uuid
        scanResult = result
        if (sameResult) {
            refreshAfterSave()
        } else {
            reloadFromScanResult()
        }
    }

    private fun reloadFromScanResult() {
        workingCorrections = scanResult.schemaCorrections
        typeCatalog = SchemaTypeCatalog.fromScanResult(scanResult)
        refreshTypePickers()
        refreshRenameList()
        refreshEnumValuesPickers()
        refreshEnumValuesList()
        refreshArgumentTypePickers()
        initArgumentPathBuilder()
        initEnumInputPathBuilder()
        refreshArgumentTypeList()
        updateSdlEditor(effectiveSdl(scanResult))
        statusLabel.text = if (scanResult.hasManualCorrections()) {
            "Manual corrections are active for this schema."
        } else {
            "Select types and enums from the schema below — no need to type names manually."
        }
    }

    private fun effectiveSdl(result: ScanResult): String {
        val effective = result.effectiveParsedSchema()
        return effective.sdlSchema ?: effective.jsonSchema.orEmpty()
    }

    private fun refreshAfterSave() {
        scanResult = view.getScanResult(scanResult.uuid) ?: scanResult
        val preservedTypeListIndex = schemaTypesList.selectedIndex
        val preservedTypeListScroll = schemaTypesScroll.verticalScrollBar.value
        val preservedOldType = selectedComboText(renameOldCombo)
        val preservedNewType = selectedComboText(renameNewCombo)

        workingCorrections = scanResult.schemaCorrections
        typeCatalog = SchemaTypeCatalog.fromScanResult(scanResult)
        refreshTypePickers(
            preferredOldType = preservedOldType,
            preferredNewType = preservedNewType,
        )
        refreshRenameList()
        refreshEnumValuesPickers()
        refreshEnumValuesList()
        refreshArgumentTypePickers()
        initArgumentPathBuilder()
        initEnumInputPathBuilder()
        refreshArgumentTypeList()
        updateSdlEditor(effectiveSdl(scanResult))

        if (preservedTypeListIndex >= 0 && preservedTypeListIndex < schemaTypesListModel.size()) {
            schemaTypesList.selectedIndex = preservedTypeListIndex
            schemaTypesList.ensureIndexIsVisible(preservedTypeListIndex)
        }
        schemaTypesScroll.verticalScrollBar.value = preservedTypeListScroll

        statusLabel.text = "Corrections saved and schema updated."
    }

    private fun refreshTypePickers(
        preferredOldType: String? = null,
        preferredNewType: String? = null,
    ) {
        val browseEntries = SchemaTypeCatalog.browseListEntries(typeCatalog)
        if (schemaTypesListModel.elements().toList() != browseEntries) {
            schemaTypesListModel.clear()
            browseEntries.forEach { schemaTypesListModel.addElement(it) }
        }

        updateComboModel(renameOldCombo, typeCatalog.renameSourceTypes, preferredOldType, dropMissingPreferred = true)
        updateComboModel(renameNewCombo, typeCatalog.renameTargetTypes, preferredNewType, dropMissingPreferred = true)
    }

    private fun updateComboModel(
        combo: JComboBox<String>,
        items: List<String>,
        preferred: String?,
        dropMissingPreferred: Boolean = false,
    ) {
        val current = (0 until combo.itemCount).map { combo.getItemAt(it) as String }
        val modelChanged = current != items
        if (modelChanged) {
            combo.model = DefaultComboBoxModel(items.toTypedArray())
        }
        val effectivePreferred = preferred?.takeIf { !dropMissingPreferred || it in items }
        when {
            effectivePreferred != null -> selectComboValue(combo, effectivePreferred)
            items.isNotEmpty() && modelChanged -> combo.selectedIndex = 0
        }
    }

    private fun updateSdlEditor(sdl: String) {
        if (sdlEditor.getQuery() == sdl) return
        sdlEditor.setPlaintext(sdl)
    }

    private fun buildRenamesPanel(): JPanel {
        val panel = JPanel(BorderLayout(8, 8))
        panel.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)

        val addRename = noFocusButton("Add rename") { addRename() }

        val top = JPanel()
        top.layout = BoxLayout(top, BoxLayout.Y_AXIS)
        top.add(
            plainHint(
                "Map a wrong or synthetic type name to the correct schema type.",
                "Click a type in the list below to fill the source field.",
            ),
        )
        top.add(
            correctionsSection("Add type rename") { content ->
                content.add(formRow("Wrong / synthetic type:", renameOldCombo))
                content.add(formRow("Correct type name:", renameNewCombo))
                content.add(formActionsRow(addRename))
            },
        )

        renameList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        val removeRename = noFocusButton("Remove selected") { removeSelectedRename() }

        val browsePanel = JPanel(BorderLayout(4, 4))
        browsePanel.border = BorderFactory.createTitledBorder("Schema types (click to pick source)")
        browsePanel.add(schemaTypesScroll, BorderLayout.CENTER)

        val renamesPanel = JPanel(BorderLayout(4, 4))
        renamesPanel.border = BorderFactory.createTitledBorder("Configured renames")
        renamesPanel.add(JScrollPane(renameList), BorderLayout.CENTER)
        val removeRow = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        removeRow.add(removeRename)
        renamesPanel.add(removeRow, BorderLayout.SOUTH)

        val listsRow = JPanel(GridLayout(1, 2, 8, 0))
        listsRow.add(browsePanel)
        listsRow.add(renamesPanel)

        panel.add(top, BorderLayout.NORTH)
        panel.add(listsRow, BorderLayout.CENTER)
        return panel
    }

    private fun buildArgumentTypesPanel(): JPanel {
        val panel = JPanel(BorderLayout(8, 8))
        panel.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)

        argumentPathRootCombo.addActionListener { onArgumentPathRootChanged() }
        argumentParentTypeCombo.addActionListener { refreshArgumentFieldPicker() }
        argumentFieldCombo.addActionListener { refreshArgumentNamePicker() }

        val pathControls = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        pathControls.add(noFocusButton("+ step") { addArgumentPathSegment() })
        pathControls.add(noFocusButton("− step") { removeLastArgumentPathSegment() })

        argumentParentTypeManualPanel.layout = BoxLayout(argumentParentTypeManualPanel, BoxLayout.Y_AXIS)
        argumentParentTypeManualPanel.alignmentX = JPanel.LEFT_ALIGNMENT
        argumentParentTypeManualPanel.add(formRow("Or pick parent type:", argumentParentTypeCombo))

        applyStatusLabelStyle(argumentPathResolvedLabel)

        val top = JPanel()
        top.layout = BoxLayout(top, BoxLayout.Y_AXIS)
        top.add(
            plainHint(
                "Walk from Query/Mutation through fields. For root fields (e.g. Query.surveys),",
                "leave Steps empty — do not pick the field name as a step.",
                "For connections, add edges then node before nested fields.",
            ),
        )
        top.add(sectionSpacer())
        top.add(
            correctionsSection("1. Find parent type") { content ->
                content.add(formRow("Start from:", argumentPathRootCombo))
                content.add(formRowMulti("Steps:", argumentPathPanel, pathControls))
                content.add(argumentPathResolvedLabel)
                content.add(argumentParentTypeManualPanel)
            },
        )
        top.add(sectionSpacer())
        top.add(
            correctionsSection("2. Set argument type") { content ->
                content.add(formRow("Field:", argumentFieldCombo))
                content.add(formRow("Argument:", argumentNameCombo))
                content.add(formRow("Correct type:", argumentTypeCombo))
                content.add(
                    plainHint(
                        "Types not in the schema yet (e.g. SurveyCategoryEnum) can be typed manually.",
                        "Save corrections to create the enum stub, then add values on the Enum Values tab.",
                    ),
                )
                content.add(formActionsRow(noFocusButton("Add / update override") { addArgumentTypeOverride() }))
            },
        )

        argumentTypeList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        argumentTypeList.visibleRowCount = 8
        argumentTypeList.fixedCellHeight = 18
        argumentTypeList.addListSelectionListener(ListSelectionListener {
            val selected = argumentTypeList.selectedValue ?: return@ListSelectionListener
            val keyPart = selected.substringBefore(" → ")
            val typePart = selected.substringAfter(" → ")
            val parts = keyPart.split('.')
            if (parts.size != 3) return@ListSelectionListener
            clearArgumentPathSegments()
            selectComboValue(argumentParentTypeCombo, parts[0])
            argumentParentTypeManualPanel.isVisible = true
            refreshArgumentFieldPicker(preferredFieldName = parts[1])
            refreshArgumentNamePicker(preferredArgumentName = parts[2])
            selectComboValue(argumentTypeCombo, typePart)
            onArgumentPathChanged()
        })
        val removeOverride = noFocusButton("Remove selected") { removeSelectedArgumentTypeOverride() }

        val scroll = JScrollPane(argumentTypeList)
        scroll.preferredSize = Dimension(0, 160)

        val overridesPanel = JPanel(BorderLayout(4, 4))
        overridesPanel.border = BorderFactory.createTitledBorder("Configured overrides")
        overridesPanel.add(scroll, BorderLayout.CENTER)
        val removeRow = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        removeRow.add(removeOverride)
        overridesPanel.add(removeRow, BorderLayout.SOUTH)

        panel.add(top, BorderLayout.NORTH)
        panel.add(overridesPanel, BorderLayout.CENTER)
        return panel
    }

    private fun effectiveSchema(): GraphQLSchema = scanResult.effectiveParsedSchema().schema

    private fun containerTypeName(container: GraphQLFieldsContainer): String? {
        return when (container) {
            is GraphQLObjectType -> container.name
            is GraphQLInterfaceType -> container.name
            else -> null
        }
    }

    private fun initArgumentPathBuilder() {
        val roots = SchemaPathWalker.rootTypeNames(effectiveSchema())
        updateComboModel(
            argumentPathRootCombo,
            roots,
            selectedComboText(argumentPathRootCombo) ?: roots.firstOrNull(),
            dropMissingPreferred = true,
        )
        if (argumentPathSegmentCombos.isEmpty()) {
            addArgumentPathSegment()
        } else {
            refreshAllArgumentPathSegmentOptions()
        }
        onArgumentPathChanged()
    }

    private fun onArgumentPathRootChanged() {
        clearArgumentPathSegments()
        addArgumentPathSegment()
        onArgumentPathChanged()
    }

    private fun clearArgumentPathSegments() {
        argumentPathSegmentCombos.forEach { argumentPathPanel.remove(it) }
        argumentPathSegmentCombos.clear()
    }

    private fun addArgumentPathSegment() {
        if (argumentPathSegmentCombos.size >= MAX_PATH_DEPTH) return
        val index = argumentPathSegmentCombos.size
        val combo = JComboBox<String>().apply {
            isEditable = true
            applyInputEnumComboWidth(this)
        }
        argumentPathSegmentCombos.add(combo)
        combo.addActionListener {
            val changedIndex = argumentPathSegmentCombos.indexOf(combo)
            if (changedIndex >= 0) {
                onArgumentPathSegmentChanged(changedIndex)
            }
        }
        argumentPathPanel.add(combo)
        refreshArgumentPathSegmentOptions(index)
        argumentPathPanel.revalidate()
        argumentPathPanel.repaint()
    }

    private fun removeLastArgumentPathSegment() {
        if (argumentPathSegmentCombos.isEmpty()) return
        val combo = argumentPathSegmentCombos.removeAt(argumentPathSegmentCombos.lastIndex)
        argumentPathPanel.remove(combo)
        argumentPathPanel.revalidate()
        argumentPathPanel.repaint()
        onArgumentPathChanged()
    }

    private fun onArgumentPathSegmentChanged(changedIndex: Int) {
        for (index in changedIndex + 1 until argumentPathSegmentCombos.size) {
            refreshArgumentPathSegmentOptions(index)
        }
        onArgumentPathChanged()
    }

    private fun refreshAllArgumentPathSegmentOptions() {
        argumentPathSegmentCombos.indices.forEach { refreshArgumentPathSegmentOptions(it) }
    }

    private fun refreshArgumentPathSegmentOptions(segmentIndex: Int) {
        val schema = effectiveSchema()
        val root = selectedComboText(argumentPathRootCombo) ?: return
        val priorSegments = argumentPathSegmentCombos
            .take(segmentIndex)
            .mapNotNull { selectedComboText(it) }
            .filter { it.isNotBlank() }
        val container = SchemaPathWalker.walk(schema, root, priorSegments) ?: return
        val options = SchemaPathWalker.segmentOptions(schema, container)
        val combo = argumentPathSegmentCombos[segmentIndex]
        val preferred = selectedComboText(combo)
        updateComboModel(combo, options, preferred, dropMissingPreferred = true)
    }

    private fun onArgumentPathChanged() {
        val resolved = resolveArgumentPathType()
        argumentPathResolvedLabel.text = when {
            resolved != null -> "→ $resolved"
            argumentPathSegmentCombos.any { !selectedComboText(it).isNullOrBlank() } -> "→ (incomplete path)"
            else -> "→ use steps above, or pick parent type below"
        }
        argumentParentTypeManualPanel.isVisible = resolved == null
        if (resolved != null) {
            selectComboValue(argumentParentTypeCombo, resolved)
            refreshArgumentFieldPicker()
        }
        argumentParentTypeManualPanel.parent?.revalidate()
    }

    private fun effectiveArgumentParentType(): String? {
        resolveArgumentPathType()?.let { return it }
        return selectedComboText(argumentParentTypeCombo)
            ?: argumentParentTypeCombo.editor.item?.toString()?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun resolveArgumentPathType(): String? {
        val schema = effectiveSchema()
        val root = selectedComboText(argumentPathRootCombo) ?: return null
        val segments = argumentPathSegmentCombos
            .mapNotNull { selectedComboText(it) }
            .filter { it.isNotBlank() }
        val container = SchemaPathWalker.walk(schema, root, segments) ?: return null
        return containerTypeName(container)
    }

    private fun refreshArgumentTypePickers(
        preferredParentType: String? = null,
        preferredFieldName: String? = null,
        preferredArgumentName: String? = null,
        preferredArgumentType: String? = null,
    ) {
        val parentTypes = buildList {
            addAll(typeCatalog.argumentParentTypes)
            addAll(workingCorrections.argumentTypeOverrides.keys)
        }.distinct().sorted()
        updateComboModel(argumentParentTypeCombo, parentTypes, preferredParentType, dropMissingPreferred = true)
        refreshArgumentFieldPicker(preferredFieldName)
        refreshArgumentNamePicker(preferredArgumentName)
        updateComboModel(
            argumentTypeCombo,
            typeCatalog.argumentTypeOptions(referencedTypesFromCorrections()),
            preferredArgumentType,
            dropMissingPreferred = false,
        )
    }

    private fun referencedTypesFromCorrections(): List<String> {
        val fromArgs = workingCorrections.argumentTypeOverrides.values
            .flatMap { fields -> fields.values.flatMap { args -> args.values } }
            .mapNotNull { sdlType -> GraphQLErrorPathParser.normalizeTypeName(sdlType) }
        return (fromArgs + workingCorrections.enumValueOverrides.keys).distinct()
    }

    private fun refreshArgumentFieldPicker(preferredFieldName: String? = null) {
        val parentType = effectiveArgumentParentType()
        val fields = buildList {
            if (!parentType.isNullOrEmpty()) {
                addAll(typeCatalog.outputFieldsFor(parentType))
                addAll(workingCorrections.argumentTypeOverrides[parentType]?.keys.orEmpty())
            }
        }.distinct().sorted()
        updateComboModel(argumentFieldCombo, fields, preferredFieldName, dropMissingPreferred = true)
    }

    private fun refreshArgumentNamePicker(preferredArgumentName: String? = null) {
        val parentType = effectiveArgumentParentType()
        val fieldName = selectedComboText(argumentFieldCombo)
            ?: argumentFieldCombo.editor.item?.toString()?.trim()
        val arguments = buildList {
            if (!parentType.isNullOrEmpty() && !fieldName.isNullOrEmpty()) {
                addAll(typeCatalog.argumentsFor(parentType, fieldName))
                addAll(workingCorrections.argumentTypeOverrides[parentType]?.get(fieldName)?.keys.orEmpty())
            }
        }.distinct().sorted()
        updateComboModel(argumentNameCombo, arguments, preferredArgumentName, dropMissingPreferred = true)
    }

    private fun refreshArgumentTypeList() {
        argumentTypeListModel.clear()
        workingCorrections.argumentTypeOverrides.entries
            .sortedBy { it.key }
            .forEach { (parentType, fields) ->
                fields.entries.sortedBy { it.key }.forEach { (fieldName, arguments) ->
                    arguments.entries.sortedBy { it.key }.forEach { (argumentName, type) ->
                        argumentTypeListModel.addElement("$parentType.$fieldName.$argumentName → $type")
                    }
                }
            }
    }

    private fun addArgumentTypeOverride() {
        val parentType = effectiveArgumentParentType()
        val fieldName = selectedComboText(argumentFieldCombo)
            ?: argumentFieldCombo.editor.item?.toString()?.trim()
        val argumentName = selectedComboText(argumentNameCombo)
            ?: argumentNameCombo.editor.item?.toString()?.trim()
        val argumentType = selectedComboText(argumentTypeCombo)
            ?: argumentTypeCombo.editor.item?.toString()?.trim()
        if (parentType.isNullOrEmpty() || fieldName.isNullOrEmpty() ||
            argumentName.isNullOrEmpty() || argumentType.isNullOrEmpty()
        ) {
            showError("Parent type, field name, argument name, and argument type are required.")
            return
        }
        val normalizedType = if (argumentType.endsWith("!")) argumentType else "$argumentType!"
        workingCorrections = workingCorrections.withArgumentTypeOverride(
            parentType,
            fieldName,
            argumentName,
            normalizedType,
        )
        refreshArgumentTypeList()
        refreshArgumentTypePickers(
            preferredParentType = parentType,
            preferredFieldName = fieldName,
            preferredArgumentName = argumentName,
            preferredArgumentType = normalizedType,
        )
        refreshEnumStandalonePickers(preferredEnumType = normalizedType.removeSuffix("!"))
        statusLabel.text = "Argument type override added. Save corrections to apply."
    }

    private fun removeSelectedArgumentTypeOverride() {
        val selected = selectedListEntry(argumentTypeList, argumentTypeListModel) ?: return
        val keyPart = selected.substringBefore(" → ")
        val parts = keyPart.split('.')
        if (parts.size != 3) return
        workingCorrections = workingCorrections.withoutArgumentTypeOverride(parts[0], parts[1], parts[2])
        refreshArgumentTypeList()
        refreshArgumentTypePickers()
        statusLabel.text = "Argument type override removed. Save corrections to apply."
    }

    private fun buildEnumValuesPanel(): JPanel {
        val panel = JPanel(BorderLayout(8, 8))
        panel.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)

        enumKindCombo.addActionListener { refreshEnumValuesFormVisibility() }
        enumInputRootCombo.addActionListener { onEnumInputRootChanged() }

        enumStandaloneTargetPanel.layout = BoxLayout(enumStandaloneTargetPanel, BoxLayout.Y_AXIS)
        enumStandaloneTargetPanel.alignmentX = JPanel.LEFT_ALIGNMENT
        enumStandaloneTargetPanel.add(formRow("Enum type:", enumTypeCombo))

        val inputPathControls = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        inputPathControls.add(noFocusButton("+ step") { addEnumInputPathSegment() })
        inputPathControls.add(noFocusButton("− step") { removeLastEnumInputPathSegment() })

        enumInputTargetPanel.layout = BoxLayout(enumInputTargetPanel, BoxLayout.Y_AXIS)
        enumInputTargetPanel.alignmentX = JPanel.LEFT_ALIGNMENT
        enumInputTargetPanel.add(formRow("Root input type:", enumInputRootCombo))
        enumInputTargetPanel.add(formRowMulti("Field path:", enumInputPathPanel, inputPathControls))
        applyStatusLabelStyle(enumInputPathResolvedLabel)
        enumInputTargetPanel.add(enumInputPathResolvedLabel)

        val top = JPanel()
        top.layout = BoxLayout(top, BoxLayout.Y_AXIS)
        top.add(
            plainHint(
                "Set allowed values for a standalone enum type (e.g. ProfilePictureSizes)",
                "or an input object field at any depth (e.g. FilterInput.user.status).",
            ),
        )
        top.add(sectionSpacer())
        top.add(
            correctionsSection("1. Choose target") { content ->
                content.add(formRow("Target:", enumKindCombo))
                content.add(enumStandaloneTargetPanel)
                content.add(enumInputTargetPanel)
            },
        )
        top.add(sectionSpacer())
        top.add(
            correctionsSection("2. Set allowed values") { content ->
                content.add(formRow("Allowed values (comma-separated):", enumValuesField))
                content.add(formActionsRow(noFocusButton("Add / update override") { addEnumValueOverride() }))
            },
        )

        enumValuesList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        enumValuesList.visibleRowCount = 8
        enumValuesList.fixedCellHeight = 18
        enumValuesList.addListSelectionListener(ListSelectionListener {
            val selected = enumValuesList.selectedValue ?: return@ListSelectionListener
            val keyPart = selected.substringBefore(" → ")
            val valuesPart = selected.substringAfter(" → ")
            enumValuesField.text = valuesPart
            if (keyPart.startsWith("[input] ")) {
                val path = keyPart.removePrefix("[input] ")
                val parts = path.split('.')
                if (parts.size < 2) return@ListSelectionListener
                selectComboValue(enumKindCombo, ENUM_KIND_INPUT_FIELD)
                refreshEnumValuesFormVisibility()
                refreshEnumInputPickers(parts[0], parts.drop(1))
            } else if (keyPart.startsWith("[enum] ")) {
                selectComboValue(enumKindCombo, ENUM_KIND_STANDALONE)
                refreshEnumValuesFormVisibility()
                refreshEnumStandalonePickers(keyPart.removePrefix("[enum] "))
            }
        })
        val removeOverride = noFocusButton("Remove selected") { removeSelectedEnumValueOverride() }

        val scroll = JScrollPane(enumValuesList)
        scroll.preferredSize = Dimension(0, 160)

        val overridesPanel = JPanel(BorderLayout(4, 4))
        overridesPanel.border = BorderFactory.createTitledBorder("Configured overrides")
        overridesPanel.add(scroll, BorderLayout.CENTER)
        val removeRow = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        removeRow.add(removeOverride)
        overridesPanel.add(removeRow, BorderLayout.SOUTH)

        panel.add(top, BorderLayout.NORTH)
        panel.add(overridesPanel, BorderLayout.CENTER)
        refreshEnumValuesFormVisibility()
        return panel
    }

    private fun refreshEnumValuesFormVisibility() {
        val inputField = selectedComboText(enumKindCombo) == ENUM_KIND_INPUT_FIELD
        enumStandaloneTargetPanel.isVisible = !inputField
        enumInputTargetPanel.isVisible = inputField
        enumStandaloneTargetPanel.parent?.revalidate()
        enumInputTargetPanel.parent?.revalidate()
    }

    private fun initEnumInputPathBuilder() {
        val roots = SchemaPathWalker.inputTypeNames(effectiveSchema())
        updateComboModel(
            enumInputRootCombo,
            roots,
            selectedComboText(enumInputRootCombo) ?: roots.firstOrNull(),
            dropMissingPreferred = true,
        )
        if (enumInputPathSegmentCombos.isEmpty()) {
            addEnumInputPathSegment()
        } else {
            refreshAllEnumInputPathSegmentOptions()
            onEnumInputPathChanged()
        }
    }

    private fun onEnumInputRootChanged() {
        clearEnumInputPathSegments()
        addEnumInputPathSegment()
        onEnumInputPathChanged()
    }

    private fun clearEnumInputPathSegments() {
        enumInputPathSegmentCombos.forEach { enumInputPathPanel.remove(it) }
        enumInputPathSegmentCombos.clear()
    }

    private fun addEnumInputPathSegment() {
        if (enumInputPathSegmentCombos.size >= MAX_PATH_DEPTH) return
        val combo = JComboBox<String>().apply {
            isEditable = true
            applyInputEnumComboWidth(this)
        }
        enumInputPathSegmentCombos.add(combo)
        combo.addActionListener {
            val changedIndex = enumInputPathSegmentCombos.indexOf(combo)
            if (changedIndex >= 0) {
                onEnumInputPathSegmentChanged(changedIndex)
            }
        }
        enumInputPathPanel.add(combo)
        refreshEnumInputPathSegmentOptions(enumInputPathSegmentCombos.lastIndex)
        enumInputPathPanel.revalidate()
        enumInputPathPanel.repaint()
    }

    private fun removeLastEnumInputPathSegment() {
        if (enumInputPathSegmentCombos.isEmpty()) return
        val combo = enumInputPathSegmentCombos.removeAt(enumInputPathSegmentCombos.lastIndex)
        enumInputPathPanel.remove(combo)
        enumInputPathPanel.revalidate()
        enumInputPathPanel.repaint()
        onEnumInputPathChanged()
    }

    private fun onEnumInputPathSegmentChanged(changedIndex: Int) {
        for (index in changedIndex + 1 until enumInputPathSegmentCombos.size) {
            refreshEnumInputPathSegmentOptions(index)
        }
        onEnumInputPathChanged()
    }

    private fun refreshAllEnumInputPathSegmentOptions() {
        enumInputPathSegmentCombos.indices.forEach { refreshEnumInputPathSegmentOptions(it) }
    }

    private fun refreshEnumInputPathSegmentOptions(segmentIndex: Int) {
        val schema = effectiveSchema()
        val root = selectedComboText(enumInputRootCombo) ?: return
        val priorSegments = enumInputPathSegmentCombos
            .take(segmentIndex)
            .mapNotNull { selectedComboText(it) }
            .filter { it.isNotBlank() }
        var currentType = root
        for (segment in priorSegments) {
            val nextType = SchemaPathWalker.inputFieldBaseType(schema, currentType, segment) ?: return
            if (!SchemaPathWalker.isNestedInputType(schema, nextType)) return
            currentType = nextType
        }
        val allFields = SchemaPathWalker.inputFieldNames(schema, currentType)
        val isLast = segmentIndex == enumInputPathSegmentCombos.lastIndex
        val options = if (isLast) {
            allFields
        } else {
            allFields.filter { field ->
                val baseType = SchemaPathWalker.inputFieldBaseType(schema, currentType, field) ?: return@filter false
                SchemaPathWalker.isNestedInputType(schema, baseType)
            }
        }
        val combo = enumInputPathSegmentCombos[segmentIndex]
        val preferred = selectedComboText(combo)
        updateComboModel(combo, options, preferred, dropMissingPreferred = true)
    }

    private fun onEnumInputPathChanged() {
        val resolved = resolveEnumInputField()
        enumInputPathResolvedLabel.text = if (resolved != null) {
            "→ ${resolved.first}.${resolved.second}"
        } else {
            "→ (incomplete path)"
        }
    }

    private fun resolveEnumInputField(): Pair<String, String>? {
        val root = selectedComboText(enumInputRootCombo) ?: return null
        val segments = enumInputPathSegmentCombos
            .mapNotNull { selectedComboText(it) }
            .filter { it.isNotBlank() }
        if (segments.isEmpty()) return null
        return SchemaPathWalker.resolveInputFieldPath(effectiveSchema(), root, segments)
    }

    private fun enumInputDisplayPath(root: String, segments: List<String>): String {
        return listOf(root).plus(segments).joinToString(".")
    }

    private fun inputEnumDisplayPath(leafInputType: String, fieldName: String): String {
        workingCorrections.inputEnumFieldDisplayPaths[leafInputType]?.get(fieldName)?.let { return it }
        return SchemaPathWalker.findInputFieldDisplayPath(effectiveSchema(), leafInputType, fieldName)
    }

    private fun findInputOverrideByDisplayPath(displayPath: String): Pair<String, String>? {
        for ((leafType, paths) in workingCorrections.inputEnumFieldDisplayPaths) {
            for ((fieldName, path) in paths) {
                if (path == displayPath) {
                    return leafType to fieldName
                }
            }
        }
        val schema = effectiveSchema()
        for ((leafType, fields) in workingCorrections.inputEnumFieldOverrides) {
            for (fieldName in fields.keys) {
                if (inputEnumDisplayPath(leafType, fieldName) == displayPath) {
                    return leafType to fieldName
                }
            }
        }
        val dotIndex = displayPath.lastIndexOf('.')
        if (dotIndex > 0) {
            val leafType = displayPath.substring(0, dotIndex)
            val fieldName = displayPath.substring(dotIndex + 1)
            if (workingCorrections.inputEnumFieldOverrides[leafType]?.containsKey(fieldName) == true) {
                return leafType to fieldName
            }
        }
        return null
    }

    private fun applyInputEnumComboWidth(combo: JComboBox<String>) {
        val height = combo.preferredSize.height
        combo.preferredSize = Dimension(INPUT_ENUM_COMBO_WIDTH, height)
        combo.minimumSize = Dimension(INPUT_ENUM_COMBO_WIDTH, height)
        combo.maximumSize = Dimension(INPUT_ENUM_COMBO_WIDTH, height)
    }

    private fun selectedListEntry(list: JList<String>, model: DefaultListModel<String>): String? {
        val index = list.selectedIndex
        if (index < 0 || index >= model.size()) return null
        return model.getElementAt(index)
    }

    private fun noFocusButton(label: String, action: () -> Unit): JButton {
        return JButton(label).also { button ->
            button.isFocusable = false
            button.addActionListener { action() }
        }
    }

    private fun plainHint(vararg lines: String): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.isOpaque = false
        panel.border = BorderFactory.createEmptyBorder(0, 4, 8, 4)
        panel.alignmentX = JPanel.LEFT_ALIGNMENT
        lines.forEach { line ->
            panel.add(JLabel(line).also { it.alignmentX = JPanel.LEFT_ALIGNMENT })
        }
        return panel
    }

    private fun correctionsSection(title: String, configure: (JPanel) -> Unit): JPanel {
        val section = JPanel()
        section.layout = BoxLayout(section, BoxLayout.Y_AXIS)
        section.border = BorderFactory.createTitledBorder(title)
        section.alignmentX = JPanel.LEFT_ALIGNMENT
        val content = JPanel()
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.alignmentX = JPanel.LEFT_ALIGNMENT
        content.border = BorderFactory.createEmptyBorder(4, 8, 8, 8)
        configure(content)
        section.add(content)
        return section
    }

    private fun formLabel(text: String): JLabel {
        return JLabel(text).also { label ->
            label.preferredSize = Dimension(FORM_LABEL_WIDTH, label.preferredSize.height)
        }
    }

    private fun formRow(label: String, field: java.awt.Component): JPanel {
        val row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        row.add(formLabel(label))
        row.add(field)
        row.alignmentX = JPanel.LEFT_ALIGNMENT
        row.maximumSize = Dimension(Int.MAX_VALUE, row.preferredSize.height)
        return row
    }

    private fun formRowMulti(label: String, vararg fields: java.awt.Component): JPanel {
        val row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        row.add(formLabel(label))
        fields.forEach { row.add(it) }
        row.alignmentX = JPanel.LEFT_ALIGNMENT
        row.maximumSize = Dimension(Int.MAX_VALUE, row.preferredSize.height)
        return row
    }

    private fun formActionsRow(vararg buttons: JButton): JPanel {
        val row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        row.border = BorderFactory.createEmptyBorder(4, FORM_LABEL_WIDTH + 8, 0, 0)
        buttons.forEach { row.add(it) }
        row.alignmentX = JPanel.LEFT_ALIGNMENT
        row.maximumSize = Dimension(Int.MAX_VALUE, row.preferredSize.height)
        return row
    }

    private fun applyStatusLabelStyle(label: JLabel) {
        label.alignmentX = JPanel.LEFT_ALIGNMENT
        label.border = BorderFactory.createEmptyBorder(2, FORM_LABEL_WIDTH + 8, 4, 4)
    }

    private fun sectionSpacer(): java.awt.Component {
        return Box.createVerticalStrut(8).also { it.maximumSize = Dimension(Int.MAX_VALUE, 8) }
    }

    private inner class SchemaTypeListCellRenderer : DefaultListCellRenderer() {
        @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
        override fun getListCellRendererComponent(
            list: JList<*>?,
            value: Any?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean,
        ): java.awt.Component {
            val label = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus) as JLabel
            val text = value?.toString().orEmpty()
            when {
                typeCatalog.isSpacer(text) -> {
                    label.text = " "
                    label.border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
                    label.isEnabled = false
                }
                typeCatalog.isSectionHeader(text) -> {
                    label.text = text
                    label.font = label.font.deriveFont(Font.BOLD)
                    label.border = BorderFactory.createEmptyBorder(0, 4, 0, 4)
                    label.isEnabled = false
                    label.background = list?.background ?: label.background
                    label.foreground = list?.foreground ?: label.foreground
                }
            }
            return label
        }
    }

    private fun buildSdlPanel(): JPanel {
        val wrapper = JPanel(BorderLayout(8, 8))
        wrapper.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)

        val top = JPanel()
        top.layout = BoxLayout(top, BoxLayout.Y_AXIS)
        top.add(
            plainHint(
                "Edit the merged SDL directly. Changes are validated before applying.",
            ),
        )
        top.add(sectionSpacer())
        top.add(
            correctionsSection("SDL") { content ->
                content.add(
                    formActionsRow(
                        noFocusButton("Save SDL (validate & apply)") { saveSdl() },
                    ),
                )
            },
        )

        val editorPanel = BorderPanel(0)
        val search = GraphQLEditorSearchPanel(sdlEditor.textPane)
        editorPanel.add(sdlEditor, BorderLayout.CENTER)
        editorPanel.add(search, BorderLayout.SOUTH)

        wrapper.add(top, BorderLayout.NORTH)
        wrapper.add(editorPanel, BorderLayout.CENTER)
        return wrapper
    }

    private fun selectedComboText(combo: JComboBox<String>): String? {
        val fromItem = (combo.selectedItem as? String)?.trim()
        if (!fromItem.isNullOrEmpty()) return fromItem
        return combo.editor.item?.toString()?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun selectComboValue(combo: JComboBox<String>, value: String) {
        combo.selectedItem = value
        if (combo.selectedItem != value) {
            combo.editor.item = value
        }
    }

    private fun addRename() {
        val oldName = selectedComboText(renameOldCombo) ?: renameOldCombo.editor.item?.toString()?.trim()
        val newName = selectedComboText(renameNewCombo) ?: renameNewCombo.editor.item?.toString()?.trim()
        if (oldName.isNullOrEmpty() || newName.isNullOrEmpty()) {
            showError("Both type names are required.")
            return
        }
        workingCorrections = workingCorrections.withRename(oldName, newName)
        refreshRenameList()
        refreshTypePickers(
            preferredOldType = oldName,
            preferredNewType = newName,
        )
    }

    private fun removeSelectedRename() {
        val selected = renameList.selectedValue ?: return
        val parts = selected.split(" → ", limit = 2)
        if (parts.size != 2) return
        workingCorrections = workingCorrections.copy(
            typeRenames = workingCorrections.typeRenames - parts[0],
        )
        refreshRenameList()
        refreshTypePickers()
    }

    private fun refreshRenameList() {
        renameListModel.clear()
        workingCorrections.typeRenames.entries.sortedBy { it.key }.forEach { (oldName, newName) ->
            renameListModel.addElement("$oldName → $newName")
        }
    }

    private fun refreshEnumValuesPickers() {
        refreshEnumStandalonePickers()
        refreshEnumInputPickers()
    }

    private fun refreshEnumStandalonePickers(preferredEnumType: String? = null) {
        val enumTypes = buildList {
            addAll(typeCatalog.enumTypes.map { it.name })
            addAll(workingCorrections.enumValueOverrides.keys)
            addAll(referencedTypesFromCorrections().filter { it.endsWith("Enum") || it.endsWith("Sizes") })
        }.distinct().sorted()
        updateComboModel(enumTypeCombo, enumTypes, preferredEnumType, dropMissingPreferred = true)
    }

    private fun refreshEnumInputPickers(
        preferredRootInput: String? = null,
        preferredFieldPath: List<String> = emptyList(),
    ) {
        val roots = buildList {
            addAll(SchemaPathWalker.inputTypeNames(effectiveSchema()))
            addAll(workingCorrections.inputEnumFieldOverrides.keys)
        }.distinct().sorted()
        updateComboModel(enumInputRootCombo, roots, preferredRootInput, dropMissingPreferred = true)
        setEnumInputPathSegments(preferredFieldPath)
        onEnumInputPathChanged()
    }

    private fun setEnumInputPathSegments(segments: List<String>) {
        clearEnumInputPathSegments()
        if (segments.isEmpty()) {
            addEnumInputPathSegment()
            return
        }
        segments.forEach { _ -> addEnumInputPathSegment() }
        segments.forEachIndexed { index, segment ->
            selectComboValue(enumInputPathSegmentCombos[index], segment)
            refreshEnumInputPathSegmentOptions(index)
        }
    }

    private fun refreshEnumValuesList() {
        enumValuesListModel.clear()
        workingCorrections.enumValueOverrides.entries
            .sortedBy { it.key }
            .forEach { (enumType, values) ->
                enumValuesListModel.addElement("[enum] $enumType → ${values.joinToString(", ")}")
            }
        workingCorrections.inputEnumFieldOverrides.entries
            .sortedBy { it.key }
            .forEach { (inputType, fields) ->
                fields.entries.sortedBy { it.key }.forEach { (fieldName, values) ->
                    val displayPath = inputEnumDisplayPath(inputType, fieldName)
                    enumValuesListModel.addElement("[input] $displayPath → ${values.joinToString(", ")}")
                }
            }
    }

    private fun addEnumValueOverride() {
        val values = parseAllowedValues(enumValuesField.text)
        if (values.isEmpty()) {
            showError("At least one allowed value is required.")
            return
        }
        if (selectedComboText(enumKindCombo) == ENUM_KIND_INPUT_FIELD) {
            val resolved = resolveEnumInputField()
            if (resolved == null) {
                showError("Root input type and a complete field path are required.")
                return
            }
            val (leafInputType, fieldName) = resolved
            val root = selectedComboText(enumInputRootCombo).orEmpty()
            val pathSegments = enumInputPathSegmentCombos.mapNotNull { selectedComboText(it) }.filter { it.isNotBlank() }
            val displayPath = enumInputDisplayPath(root, pathSegments)
            workingCorrections = workingCorrections.withInputEnumFieldOverride(
                leafInputType,
                fieldName,
                values,
                displayPath = displayPath,
            )
            refreshEnumInputPickers(root, pathSegments)
            statusLabel.text = "Input enum override added for $displayPath. Save corrections to apply."
        } else {
            val enumType = selectedComboText(enumTypeCombo)
                ?: enumTypeCombo.editor.item?.toString()?.trim()
            if (enumType.isNullOrEmpty()) {
                showError("Enum type is required.")
                return
            }
            workingCorrections = workingCorrections.withEnumValueOverride(enumType, values)
            refreshEnumStandalonePickers(preferredEnumType = enumType)
            statusLabel.text = "Enum type override added. Save corrections to apply."
        }
        enumValuesField.text = values.joinToString(", ")
        refreshEnumValuesList()
    }

    private fun removeSelectedEnumValueOverride() {
        val selected = selectedListEntry(enumValuesList, enumValuesListModel)
        if (selected == null) {
            statusLabel.text = "Select an override to remove."
            return
        }
        val keyPart = selected.substringBefore(" → ")
        when {
            keyPart.startsWith("[enum] ") -> {
                val enumType = keyPart.removePrefix("[enum] ").trim()
                workingCorrections = workingCorrections.withoutEnumValueOverride(enumType)
            }
            keyPart.startsWith("[input] ") -> {
                val path = keyPart.removePrefix("[input] ").trim()
                val resolved = findInputOverrideByDisplayPath(path)
                if (resolved == null) {
                    showError("Could not resolve input field override: $path")
                    return
                }
                workingCorrections = workingCorrections.withoutInputEnumFieldOverride(resolved.first, resolved.second)
            }
            else -> {
                statusLabel.text = "Could not parse selected override."
                return
            }
        }
        refreshEnumValuesList()
        refreshEnumValuesPickers()
        statusLabel.text = "Enum override removed. Save corrections to apply."
    }

    private fun parseAllowedValues(raw: String): List<String> {
        return raw.split(',')
            .map { it.trim().removeSurrounding("\"", "\"").removeSurrounding("'", "'") }
            .filter { it.isNotEmpty() }
    }

    private fun revertCorrections() {
        val confirm = JOptionPane.showConfirmDialog(
            this,
            "Remove all manual corrections for this schema?",
            "Revert corrections",
            JOptionPane.YES_NO_OPTION,
        )
        if (confirm != JOptionPane.YES_OPTION) return
        workingCorrections = SchemaCorrections.EMPTY
        if (view.revertSchemaCorrections(scanResult)) {
            refreshAfterSave()
            statusLabel.text = "Corrections reverted."
        }
    }

    private fun saveCorrections() {
        if (view.applySchemaCorrections(scanResult, workingCorrections)) {
            refreshAfterSave()
        } else {
            showError("Failed to apply corrections. Check the error log for SDL validation details.")
        }
    }

    private fun saveSdl() {
        val sdl = sdlEditor.getQuery()
        if (view.saveSdlSchema(scanResult, sdl)) {
            refreshAfterSave()
        } else {
            showError("SDL validation failed. Check the error log for details.")
        }
    }

    private fun showError(message: String) {
        JOptionPane.showMessageDialog(this, message, "Schema corrections", JOptionPane.ERROR_MESSAGE)
    }
}
