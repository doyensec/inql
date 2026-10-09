package inql.scanner.scanresults

import burp.Burp
import inql.scanner.MergeSource
import inql.scanner.ScanResult
import inql.scanner.ScannerTab
import inql.scanner.SchemaDiscoverySource
import inql.ui.BorderPanel
import inql.ui.BoxPanel
import inql.ui.FlowPanel
import inql.ui.SimpleDocumentListener
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.io.File
import javax.swing.*
import javax.swing.filechooser.FileNameExtensionFilter

class SchemaMergeDialog(private val scannerTab: ScannerTab) :
    JDialog(Burp.Montoya.userInterface().swingUtils().suiteFrame(), "Merge schema", true) {

    private class Candidate(val tab: ScannerTab, val result: ScanResult) {
        override fun toString() =
            "${tab.getTabTitle()} — ${result.schemaDiscoverySource.treeLabelSuffix} — ${result.host}"
    }

    private val currentHosts = scannerTab.referencedHosts()

    private val candidates = scannerTab.scanner.getScannerTabs()
        .filter { tab -> tab !== scannerTab && currentHosts.any { scannerTab.scanner.tabReferencesHost(tab, it) } }
        .mapNotNull { tab -> tab.primaryScanResult()?.let { Candidate(tab, it) } }

    private val tabRadio = JRadioButton("Another InQL tab for ${currentHosts.firstOrNull().orEmpty()}")
    private val fileRadio = JRadioButton("Schema file (.json / .graphql)")
    private val tabCombo = JComboBox(candidates.toTypedArray())
    private val pathField = JTextField(32)
    private val browseButton = JButton("Browse…")
    private val mergeButton = JButton("Merge")

    init {
        ButtonGroup().apply {
            add(tabRadio)
            add(fileRadio)
        }
        candidates.firstOrNull { it.result.schemaDiscoverySource == SchemaDiscoverySource.HISTORY }
            ?.let { tabCombo.selectedItem = it }
        tabRadio.isEnabled = candidates.isNotEmpty()
        (if (candidates.isEmpty()) fileRadio else tabRadio).isSelected = true

        browseButton.addActionListener { browse() }
        mergeButton.addActionListener { merge() }
        listOf(tabRadio, fileRadio).forEach { it.addActionListener { updateState() } }
        tabCombo.addActionListener { updateState() }
        pathField.document.addDocumentListener(SimpleDocumentListener(::updateState))

        val content = BoxPanel(
            BoxLayout.PAGE_AXIS,
            5,
            JLabel("Merge `${scannerTab.getTabTitle()}` with:"),
            tabRadio,
            row(tabCombo),
            fileRadio,
            row(pathField, browseButton),
            JLabel(
                "The current tab's schema takes precedence on conflicts. Result is a snapshot saved in a new tab. "",
            ),
        )
        content.components.forEach { (it as? JComponent)?.alignmentX = Component.LEFT_ALIGNMENT }

        val buttons = FlowPanel(FlowLayout.RIGHT).apply {
            add(JButton("Cancel").apply { addActionListener { dispose() } })
            add(mergeButton)
        }
        contentPane = BorderPanel(10).apply {
            add(content, BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }
        rootPane.defaultButton = mergeButton
        updateState()
        Burp.Montoya.userInterface().applyThemeToComponent(this)
        pack()
        setLocationRelativeTo(owner)
    }

    private fun row(vararg components: JComponent) = FlowPanel(FlowLayout.LEFT).apply {
        border = BorderFactory.createEmptyBorder(0, 20, 0, 0)
        components.forEach { add(it) }
    }

    private fun selectedCandidate() = tabCombo.selectedItem as? Candidate

    private fun selectedFile() = pathField.text.trim().takeIf { it.isNotEmpty() && File(it).isFile }

    private fun updateState() {
        tabCombo.isEnabled = tabRadio.isSelected
        pathField.isEnabled = fileRadio.isSelected
        browseButton.isEnabled = fileRadio.isSelected
        mergeButton.isEnabled = if (tabRadio.isSelected) selectedCandidate() != null else selectedFile() != null
    }

    private fun browse() {
        val chooser = JFileChooser().apply {
            fileFilter = FileNameExtensionFilter("GraphQL Schema", "graphql", "graphqls", "json")
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            pathField.text = chooser.selectedFile.absolutePath
        }
    }

    private fun merge() {
        val source = if (tabRadio.isSelected) {
            MergeSource.Tab(selectedCandidate()?.tab ?: return)
        } else {
            MergeSource.File(selectedFile() ?: return)
        }
        dispose()
        scannerTab.mergeSchemaWith(source)
    }
}
