package inql.attacker

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonSyntaxException
import inql.InQL
import inql.Logger
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.ui.BorderPanel
import inql.ui.ErrorDialog
import inql.ui.MessageEditor
import inql.ui.MultilineLabel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.awt.BorderLayout
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.File
import java.lang.Integer.max
import java.lang.Integer.min
import javax.swing.*

class Attacker(private val inql: InQL) : BorderPanel(), ActionListener, SavesAndLoadData {

    private val coroutineScope = CoroutineScope(Dispatchers.IO)
    private val attacks = ArrayList<Attack>()
    private val urlField = JTextField()
    private val sendButton = JButton("Send").also { it.addActionListener(this) }
    private val requestEditor = Burp.Montoya.userInterface().createHttpRequestEditor()
    private val historyRequestViewer = MessageEditor(readOnly = true)
    private val historyLog = HistoryLog(this.attacks) { this.historyTableSelectionListener(it) }
    private var selected: Attack? = null

    var url: String
        get() = this.urlField.text
        set(s) {
            this.urlField.text = s
        }
    var request: HttpRequest
        get() = this.requestEditor.request
        set(r) {
            this.requestEditor.request = r
        }

    fun focus() = inql.focusTab(this)

    // Initialize UI
    init {
        // Request editor section
        val urlFieldPanel = BorderPanel().also {
            it.add(JLabel("Target: "), BorderLayout.WEST)
            it.add(this.urlField, BorderLayout.CENTER)
            it.add(sendButton, BorderLayout.EAST)
        }
        val reqEditorPanel = BorderPanel().also {
            it.add(urlFieldPanel, BorderLayout.NORTH)
            it.add(this.requestEditor.uiComponent(), BorderLayout.CENTER)
        }

        // Left section
        val leftSection = BorderPanel(5, 5).also {
            it.add(
                MultilineLabel(
                    """
                        
                Supported placeholders:

                    ${'$'}[INT:first:last] - first and last are integers, both are included in the range
                    ${'$'}[FILE:path:first:last] - absolute path and the (optional) range of lines (first line is 1 not 0)

                Current limitations: only one placeholder, no variables.
                
            """.trimIndent()
                ), BorderLayout.NORTH
            )
            it.add(reqEditorPanel, BorderLayout.CENTER)
        }
        Burp.Montoya.userInterface().applyThemeToComponent(leftSection) // TODO: check if necessary

        // Right section
        val rightSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(historyLog.table),
            historyRequestViewer
        )

        // Main layout
        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSection
        )
        horizontalSplit.resizeWeight = 0.4
        this.add(horizontalSplit)
    }

    private fun generateAttackRequest(): Attack? {
        val body = this.request.bodyToString().replace(Regex("\\\\[rnt]"), "")
        var parsed: JsonElement
        try {
            parsed = Gson().fromJson(body, JsonElement::class.java)
        } catch (_: JsonSyntaxException) {
            Logger.error("Failed parsing request body as JSON")
            ErrorDialog("Failed parsing request body as JSON")
            return null
        }
        if (parsed.isJsonArray) {
            parsed = parsed.asJsonArray[0]
        }
        var query = parsed.asJsonObject["query"].asString

        var prefix = ""
        var suffix = ""

        while (true) {
            // split string in "pfx { query } sfx"
            var match = Regex("^([^{]*?)\\{(.+)}([^}]*?)$").matchEntire(query)
            if (match == null || match.groups.size != 4) {
                Logger.warning("Cannot find SelectionSet (\"{ }\") block in query $query")
                return null
            }

            val pfx = match.groupValues[1]
            query = match.groupValues[2]
            val sfx = match.groupValues[3]

            // look for placeholders
            val intPlaceholder = Regex("^(.*?)\\\$\\[(INT):(\\d+:\\d+)\\](.*)\$").matchEntire(pfx)
            val filePlaceholder = Regex("^(.*?)\\\$\\[(FILE):([^:]+(?::\\d+:\\d+)?)\\](.*)\$").matchEntire(pfx)

            match = intPlaceholder ?: filePlaceholder
            if (match == null || match.groups.size != 5) {
                prefix = "$prefix$pfx{"
                suffix = "}$sfx$suffix"
                continue
            }

            val leading = match.groupValues[1]
            val op = match.groupValues[2]
            val args = match.groupValues[3].split(':')
            val trailing = match.groupValues[4]
            var start: Int
            var end: Int

            val exploit = StringBuilder()

            when (op) {
                "INT" -> {
                    // $[INT:first:last]
                    start = args[0].toInt()
                    end = args[1].toInt()
                    for (n in start..end) {
                        exploit.append(" op${n + 1}: $leading$n$trailing{$query}$sfx")
                    }
                }

                "FILE" -> {
                    // $[FILE:path] and $[FILE:path:first:last]
                    val path = args[0]
                    val lines = File(path).readLines()
                    // line nr is 1-indexed :/
                    start = 1
                    end = lines.size
                    if (args.size == 3) {
                        start = min(args[1].toInt() - 1, 1)
                        end = max(args[2].toInt() - 1, lines.size)
                    }
                    for (n in start..end) {
                        exploit.append("op${n}: $leading${lines[n - 1]}$trailing{$query}$sfx")
                    }
                }

                else -> continue
            }

            // Successful processing ends up here
            val exploitQuery = prefix + exploit.toString() + suffix
            val newQuery = JsonObject()
            newQuery.addProperty("query", exploitQuery)
            val newBody = Gson().toJson(newQuery)
            val req =
                this.request.withService(burp.api.montoya.http.HttpService.httpService(this.url)).withBody(newBody)
            return Attack(this.url, req, null, start, end)
        }
    }

    override fun actionPerformed(e: ActionEvent?) {
        Logger.debug("Initiate Attack handler fired")
        val attackRequest = this.generateAttackRequest()
        if (attackRequest == null) {
            Logger.error("Failed generating attack request")
            return
        }
        Logger.debug("Attack request generated successfully")
        val rowIdx = this.attacks.size
        this.attacks.add(attackRequest)
        this.historyLog.fireTableRowsInserted(rowIdx, rowIdx)
        this.coroutineScope.launch { runAttack(rowIdx, attackRequest) }
    }

    fun refresh() {
        this.historyLog.fireTableDataChanged()
    }

    private fun runAttack(rowIdx: Int, atk: Attack) {
        val response = Burp.Montoya.http().sendRequest(atk.req)
        atk.resp = response.response()
        this.historyLog.fireTableRowsUpdated(rowIdx, rowIdx)
        if (this.selected == atk) this.historyRequestViewer.response.response = atk.resp
        Logger.info("Sent the request and received a response with status code ${atk.resp!!.statusCode()}")
        this.updateChildObjectAsync(atk)
    }

    private fun historyTableSelectionListener(rowIndex: Int) {
        val entry = this.attacks[rowIndex]
        this.selected = entry
        this.historyRequestViewer.request.request = entry.req
        this.historyRequestViewer.response.response = entry.resp
    }

    fun loadFromRequest(req: HttpRequest) {
        this.url = req.url()
        this.request = req
        this.focus()
        this.urlField.requestFocus()
    }

    override val saveStateKey: String
        get() = "Attacker"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject> = this.attacks

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setString("url", this.url)
        obj.setHttpRequest("request", this.request)
        obj.setStringList("attacks", getSaveStateKeys(this.attacks))
        return obj
    }

    override fun burpDeserialize(obj: PersistedObject) {
        this.url = obj.getString("url")
        this.request = obj.getHttpRequest("request")
        val attackIdLst = obj.getStringList("attacks")
        if (!attackIdLst.isNullOrEmpty()) {
            Logger.debug("Loading ${attackIdLst.size} Attacks from project file")
            for (attackId in attackIdLst) {
                this.attacks.add(Attack.Deserializer(attackId).get() ?: continue)
            }
            this.refresh()
        }
    }
}