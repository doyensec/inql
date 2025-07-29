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
import inql.graphql.formatting.Style
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.ui.BorderPanel
import inql.ui.ErrorDialog
import inql.ui.MessageEditor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.awt.BorderLayout
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.File
import java.awt.Color
import java.awt.Dimension
import java.awt.Font
import java.lang.Integer.max
import java.lang.Integer.min
import javax.swing.*
import javax.swing.border.EmptyBorder

class Attacker(private val inql: InQL) : BorderPanel(), ActionListener, SavesAndLoadData {

    private val coroutineScope = CoroutineScope(Dispatchers.IO)
    private val attacks = ArrayList<Attack>()
    private val urlField = JTextField()
    private val sendButton = JButton("Send").also { 
        it.addActionListener(this) 
        it.background = Style.ThemeColors.Accent
        it.foreground = Color.WHITE
        it.font = it.font.deriveFont(Font.BOLD)
        it.isBorderPainted = false
    }
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
            it.add(BorderPanel().apply {
                border = EmptyBorder(0, 10, 0, 0)
                add(sendButton, BorderLayout.CENTER)
            }, BorderLayout.EAST)
        }
        val reqEditorPanel = BorderPanel().also {
            it.add(urlFieldPanel, BorderLayout.NORTH)
            it.add(this.requestEditor.uiComponent(), BorderLayout.CENTER)
        }

        val editorPane = JEditorPane()
        editorPane.setContentType("text/html")
        editorPane.setText("""
<h2>Batch Queries</h2>
This tab allows sending hundreds of queries inside of a single HTTP request. This may be useful for testing 2FA bypasses, DoSes, and more!

<h2>How to use</h2>
To send a request with 3 batched queries, use one of the placeholders described below and add them in front of
the query to send. For example:
<pre> 
{
    "query": "query { $[INT:0:3] verify2FA(code: \"${'$'}INT\") { status } }"
}
</pre>

This will generate and send the following request:
<pre> 
{
    "query": "query { 
        op0:   verify2FA(code: \"0\") { status }  
        op1:   verify2FA(code: \"1\") { status }  
        op2:   verify2FA(code: \"2\") { status }  
    }"
}
</pre>

Supported placeholders:<br/>
- <b>${'$'}[INT:first:last]</b> with variable <b>${'$'}INT</b> - first and last are integers, works like <code>range(first,last)</code> in Python<br/>
- <b>${'$'}[FILE:path:first:last]</b> with variable <b>${'$'}FILE</b> - absolute path to a file and the (optional) range of lines (first line is 1 not 0)<br/>
<br/>
Current limitations: only one placeholder, no variables.
""")
        editorPane.setEditable(false)

        // Left section
        val leftSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(editorPane),
            reqEditorPanel,
        )

        Burp.Montoya.userInterface().applyThemeToComponent(leftSection) // TODO: check if necessary

        // Right section
        val rightSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(historyLog.table),
            historyRequestViewer,
        )

        // Main layout
        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSection,
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
                    for (n in start..<end) {
                        var tmpQuery = " op${n}: $leading$trailing{$query}$sfx"
                        tmpQuery = tmpQuery.replace("\$INT", n.toString())
                        exploit.append(tmpQuery)
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
                        start = max(args[1].toInt(), 1)
                        end = min(args[2].toInt(), lines.size)
                    }
                    for (n in start..end) {
                        var tmpQuery = " op$n: $leading$trailing{$query}$sfx"
                        tmpQuery = tmpQuery.replace("\$FILE", lines[n - 1])
                        exploit.append(tmpQuery)
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
