package inql.ui

import burp.api.montoya.core.HighlightColor
import inql.Config
import javax.swing.*

class SettingsWindow private constructor() : Window("InQL Settings") {
    companion object {
        private lateinit var instance: SettingsWindow
        fun getInstance(): SettingsWindow {
            if (!this::instance.isInitialized) instance = SettingsWindow()
            return instance
        }
    }

    class SettingsElement<T : JComponent>(val key: String, val component: T) {
        private val config = Config.getInstance()

        init {
            when (component) {
                is CheckBox -> {
                    val cb = this.component as CheckBox
                    cb.setSelected(config.getBoolean(this.key, scope = Config.Scope.EFFECTIVE_GLOBAL)!!)
                    cb.addItemListener {
                        config.set(key, cb.isSelected(), scope = Config.Scope.GLOBAL)
                    }
                }

                is Spinner -> {
                    val spinner = this.component as Spinner
                    spinner.setValue(config.getInt(this.key, scope = Config.Scope.EFFECTIVE_GLOBAL)!!)
                    spinner.addChangeListener {
                        config.set(key, spinner.getValue(), scope = Config.Scope.GLOBAL)
                    }
                }

                is ComboBox -> {
                    val cb = this.component as ComboBox
                    cb.setSelectedItem(config.getString(this.key, scope = Config.Scope.EFFECTIVE_GLOBAL)!!)
                    cb.addItemListener {
                        config.set(key, cb.getSelectedItem(), scope = Config.Scope.GLOBAL)
                    }
                }

                is TextField -> {
                    val tf = this.component as TextField
                    tf.setText(config.getString(this.key, scope = Config.Scope.EFFECTIVE_GLOBAL)!!)
                    tf.changeListener = fun() {
                        config.set(key, tf.getText(), scope = Config.Scope.GLOBAL)
                    }
                }

                is TextArea -> {
                    val ta = this.component as TextArea
                    ta.setText(config.getString(this.key, scope = Config.Scope.EFFECTIVE_GLOBAL)!!)
                    ta.changeListener = fun() {
                        config.set(key, ta.getText(), scope = Config.Scope.GLOBAL)
                    }
                }

                else -> throw NotImplementedError("This element type has not been implemented")
            }
        }
    }

    class SettingsSection(val sectionTitle: String, val description: String, vararg elements: SettingsElement<*>?) :
        BorderPanel(10) {
        init {
            val innerBox = BoxPanel(BoxLayout.Y_AXIS, gap = 0)

            for (e in elements) {
                if (e != null) {
                    innerBox.add(e.component)
                } else {
                    innerBox.add(Box.createVerticalStrut(10))
                }
            }
            val padded = BorderPanel(0, 10)
            padded.add(innerBox)

            val outerBox = BoxPanel(
                BoxLayout.Y_AXIS,
                gap = 10,
                BorderPanel(0).also { it.add(Label(sectionTitle, big = true)) },
                BorderPanel(0).also { it.add(Label(description)) },
                padded,
            )

            this.add(outerBox)
        }
    }

    init {
        // Build the different section first
        val codeGenerationSection = SettingsSection(
            "Code generation settings",
            "Use these settings to configure how the code generated by InQL will look like.",
            SettingsElement("codegen.depth", Spinner("Maximum depth of the generated queries", 1, 10)),
            SettingsElement("codegen.pad", Spinner("Number of whitespaces to use for indentation", 1, 10)),
        )

        val reportSection = SettingsSection(
            "Additional GraphQL reports",
            "Use these settings to configure additional reports generated by InQL.",
            SettingsElement("report.json", CheckBox("Dump introspection schema in JSON format")),
            SettingsElement("report.sdl", CheckBox("Dump GraphQL schema in SDL format (not implemented yet)")),
            SettingsElement("report.cycles", CheckBox("Test schema for cycles and report findings (not implemented yet)")),
            SettingsElement("report.cycles.depth", Spinner("Maximum depth of the generated queries", 1, 1000)),
        )

        val featuresSection = SettingsSection(
            "InQL Features",
            "Select which features to enable. Reloading the extension or restarting Burp may be required to apply the changes.",
            SettingsElement(
                "proxy.highlight_enabled",
                CheckBox("Enable request highlighting in Proxy")
            ),
            SettingsElement(
                "proxy.highlight_color",
                ComboBox("Request highlighting color", *HighlightColor.entries.map { it.displayName() }.toTypedArray())
            ),
            SettingsElement(
                "editor.formatting.enabled",
                CheckBox("Enable Formatting in the GraphQL editor")
            ),
            SettingsElement(
                "editor.formatting.timeout",
                Spinner("Formatting timeout (ms)", 0, 10000)
            ),
            SettingsElement(
                "editor.send_to.strip_comments",
                CheckBox("Strip GraphQL comments from the Scanner result tab when sending a request to another tool")
            ),
        )

        val integrationsSection = SettingsSection(
            "InQL Integrations",
            "Configure integrations with embedded tools.",
            SettingsElement(
                "integrations.graphiql",
                CheckBox("Enable GraphiQL")
            ),
            SettingsElement(
                "integrations.voyager",
                CheckBox("Enable GraphQL Voyager")
            ),
            SettingsElement(
                "integrations.browser.internal",
                CheckBox("Use embedded Chromium when launching IDEs")
            ),
            SettingsElement(
                "integrations.browser.external.command",
                TextField("Command to launch external browser (when not using embedded)"),
            ),
            SettingsElement(
                    "integrations.webserver.lazy",
            CheckBox("Start internal webserver lazily (when a request is sent to IDE from context menu)")
        ),
        )

        val poiSection = SettingsSection(
            "Points of interest",
            "Use these settings to configure how InQL will handle points of interest.",
            SettingsElement("report.poi", CheckBox("Enable points of interest")),
            null,
            SettingsElement("report.poi.depth", Spinner("Maximum depth of the generated queries", 1, 10)),
            SettingsElement("report.poi.format", ComboBox("Format of the generated queries", "text", "json", "both")),
            null,
            SettingsElement("report.poi.auth", CheckBox("Report points of interest that deal with authentication")),
            SettingsElement(
                "report.poi.privileged",
                CheckBox("Report points of interest that require or provide privileged access"),
            ),
            SettingsElement("report.poi.pii", CheckBox("Report points of interest that might contain or process PII")),
            SettingsElement(
                "report.poi.payment",
                CheckBox("Report points of interest that might contain or process payment information"),
            ),
            SettingsElement(
                "report.poi.database",
                CheckBox("Report points of interest that might allow direct database access"),
            ),
            SettingsElement(
                "report.poi.debugging",
                CheckBox("Report points of interest that expose debugging information"),
            ),
            SettingsElement("report.poi.files", CheckBox("Report points of interest that deal with file management")),
            SettingsElement("report.poi.deprecated", CheckBox("Report deprecated functionality")),
            SettingsElement("report.poi.custom_scalars", CheckBox("Report custom scalars")),
            null,
            SettingsElement("report.poi.custom_keywords", TextArea("Custom keywords for points of interest", 6, 20)),
        )

        val loggingLevelSection = SettingsSection(
            "Logging options",
            "Use these settings to configure the logging level of the extension.",
            SettingsElement(
                "logging.level",
                ComboBox("Logging level", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
            ),
        )

        // Build the main window
        val boxed = BoxPanel(
            BoxLayout.Y_AXIS,
            gap = 0,
            codeGenerationSection,
            JSeparator(JSeparator.HORIZONTAL),
            featuresSection,
            JSeparator(JSeparator.HORIZONTAL),
            integrationsSection,
            JSeparator(JSeparator.HORIZONTAL),
            reportSection,
            JSeparator(JSeparator.HORIZONTAL),
            poiSection,
            JSeparator(JSeparator.HORIZONTAL),
            loggingLevelSection,
            JSeparator(JSeparator.HORIZONTAL),
        )
        val padded = BorderPanel(0, 20).also { it.add(boxed) }
        val scrollable = JScrollPane(padded)
        scrollable.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        scrollable.horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED

        this.add(scrollable)

        this.autoSize()
    }
}
