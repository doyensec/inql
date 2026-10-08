package inql.attacker

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import inql.InQL
import inql.Logger
import inql.graphql.formatting.Style
import inql.savestate.SavesAndLoadData
import inql.savestate.SavesDataToProject
import inql.savestate.getSaveStateKeys
import inql.ui.BorderPanel
import inql.ui.ErrorDialog
import inql.ui.MessageEditor
import inql.ui.applyEqualSplit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextField
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
    private val historyLog = HistoryLog(
        this.attacks,
        { this.historyTableSelectionListener(it) },
        onDeleteSelected = { deleteAttacks(it) },
        onClear = { deleteAttacks(this.attacks.toList()) },
    )
    private val payloadsPanel = PayloadsPanel()
    private val resultsPanel = BatchResultsPanel()
    private val detailTabs = JTabbedPane()
    private var selected: Attack? = null
    private var runningJob: Job? = null

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

    init {
        payloadsPanel.onRefreshRequested = { payloadsPanel.refreshFromRequest(request) }
        resultsPanel.onItemSelected = { run, item -> showResultItem(run, item, switchToMessage = false) }
        resultsPanel.onItemActivated = { run, item -> showResultItem(run, item, switchToMessage = true) }

        val urlFieldPanel = BorderPanel().also {
            it.add(JLabel("Target: "), BorderLayout.WEST)
            it.add(this.urlField, BorderLayout.CENTER)
            it.add(
                BorderPanel().apply {
                    border = EmptyBorder(0, 10, 0, 0)
                    add(sendButton, BorderLayout.CENTER)
                },
                BorderLayout.EAST,
            )
        }
        val reqEditorPanel = BorderPanel().also {
            it.add(urlFieldPanel, BorderLayout.NORTH)
            it.add(this.requestEditor.uiComponent(), BorderLayout.CENTER)
        }

        val leftSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            payloadsPanel,
            reqEditorPanel,
        ).apply {
            resizeWeight = 0.38
        }

        Burp.Montoya.userInterface().applyThemeToComponent(leftSection)

        detailTabs.addTab("Request / Response", historyRequestViewer)
        detailTabs.addTab("Results", resultsPanel)
        val rightSection = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(historyLog.table),
            detailTabs,
        )

        val horizontalSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSection,
            rightSection,
        )
        horizontalSplit.applyEqualSplit(0.5)
        this.add(horizontalSplit)
    }

    override fun actionPerformed(e: ActionEvent?) {
        this.runningJob?.let { job ->
            Logger.debug("Stopping the running batch attack")
            job.cancel()
            return
        }
        Logger.debug("Initiate Attack handler fired")
        payloadsPanel.refreshFromRequest(request)
        val config = payloadsPanel.readConfig() ?: return
        val baseRequest = this.request
        val targetUrl = this.url
        setRunning(true)
        // The finally block runs on the EDT after this handler returns, so runningJob is always assigned first.
        this.runningJob = this.coroutineScope.launch {
            try {
                runBatch(baseRequest, targetUrl, config)
            } finally {
                withContext(NonCancellable + Dispatchers.Swing) {
                    runningJob = null
                    setRunning(false)
                }
            }
        }
    }

    fun refresh() {
        this.historyLog.fireTableDataChanged()
    }

    private fun setRunning(running: Boolean) {
        this.sendButton.text = if (running) "Stop" else "Send"
    }

    private suspend fun runBatch(baseRequest: HttpRequest, targetUrl: String, config: BatchAttackConfig) {
        val plan = when (val result = BatchRequestBuilder.build(baseRequest, targetUrl, config)) {
            is BatchBuildResult.Failure -> {
                ErrorDialog(result.message)
                return
            }
            is BatchBuildResult.Success -> result.plan
        }
        Logger.debug("Batch attack planned: ${plan.totalItems} items in ${plan.requestCount} request(s)")

        val run = BatchRun(plan.mode, plan.variableLabels, plan.totalItems, plan.requestCount)
        var itemOffset = 0
        try {
            for (chunk in plan.requests()) {
                coroutineContext.ensureActive()
                val attack = Attack(
                    targetUrl,
                    chunk.request,
                    null,
                    0,
                    chunk.itemCount,
                    plan.mode.label,
                    chunk.itemCount,
                    part = chunk.index + 1,
                    partCount = plan.requestCount,
                )
                attack.run = run
                withContext(Dispatchers.Swing) {
                    val rowIdx = attacks.size
                    attacks.add(attack)
                    historyLog.fireTableRowsInserted(rowIdx, rowIdx)
                    if (chunk.index == 0) selectHistoryRow(rowIdx)
                }
                val sent = sendAttack(attack)
                recordResults(run, attack, chunk, itemOffset)
                itemOffset += chunk.itemCount
                if (!sent) {
                    val where = if (plan.requestCount > 1) " (request ${attack.part}/${attack.partCount})" else ""
                    ErrorDialog("Batch attack request failed$where: ${attack.error}")
                    return
                }
            }
        } catch (e: BatchBuildException) {
            ErrorDialog(e.message ?: "Failed to build the batched request.")
        }
    }

    /** Splits the response into per-item results and adds them to the run. */
    private suspend fun recordResults(run: BatchRun, attack: Attack, chunk: BatchChunk, itemOffset: Int) {
        val outcomes = attack.resp?.let { BatchResponseParser.split(run.mode, chunk.itemCount, it.bodyToString()) }
        val items = chunk.payloads.mapIndexed { index, payloads ->
            val outcome = outcomes?.getOrNull(index)
            BatchResultItem(
                index = itemOffset + index + 1,
                localIndex = index,
                payloads = payloads,
                part = attack.part,
                status = outcome?.status ?: BatchItemStatus.FAILED,
                errors = outcome?.errors ?: attack.error.orEmpty(),
                size = outcome?.size,
                responseTimeMs = attack.responseTimeMs,
            )
        }
        withContext(NonCancellable + Dispatchers.Swing) {
            val from = run.items.size
            run.addAll(items)
            if (items.isNotEmpty()) resultsPanel.itemsAdded(run, from, run.items.size - 1)
        }
    }

    /** Sends the request and records the response or error. Returns false if no response was received. */
    private suspend fun sendAttack(atk: Attack): Boolean {
        val started = System.nanoTime()
        try {
            atk.resp = Burp.Montoya.http().sendRequest(atk.req)?.response()
            if (atk.resp == null) atk.error = "No response received"
        } catch (e: Exception) {
            atk.error = e.message ?: e.javaClass.simpleName
        }
        atk.responseTimeMs = (System.nanoTime() - started) / 1_000_000
        if (atk.error != null) {
            Logger.error("Batch attack request failed: ${atk.error}")
        } else {
            Logger.info("Sent the request and received a response with status code ${atk.resp?.statusCode()}")
        }

        // Record the result even if the attack was stopped while this request was in flight.
        val stillListed = withContext(NonCancellable + Dispatchers.Swing) {
            val rowIdx = attacks.indexOf(atk)
            if (rowIdx >= 0) historyLog.fireTableRowsUpdated(rowIdx, rowIdx)
            if (selected == atk) historyRequestViewer.response.response = atk.resp
            rowIdx >= 0
        }
        if (stillListed) this.updateChildObjectAsync(atk)
        return atk.error == null
    }

    private fun selectHistoryRow(rowIdx: Int) {
        if (rowIdx !in this.attacks.indices) return
        val table = this.historyLog.table
        table.changeSelection(rowIdx, 0, false, false)
        table.scrollRectToVisible(table.getCellRect(rowIdx, 0, true))
    }

    private fun deleteAttacks(toRemove: List<Attack>) {
        if (toRemove.isEmpty()) return
        val removeSet = toRemove.toSet()
        val keepSelected = this.selected?.takeIf { it !in removeSet }
        this.attacks.removeAll(removeSet)
        this.historyLog.fireTableDataChanged()
        if (keepSelected != null) {
            selectHistoryRow(this.attacks.indexOf(keepSelected))
        } else if (this.attacks.isNotEmpty()) {
            selectHistoryRow(this.attacks.lastIndex)
        } else {
            this.selected = null
            this.historyRequestViewer.request.request = HttpRequest.httpRequest()
            this.resultsPanel.showRun(null)
        }
        this.coroutineScope.launch {
            for (attack in toRemove) {
                attack.deleteFromProjectFile()
            }
            saveToProjectFile(false)
        }
    }

    /**
     * Selects the history row of the HTTP request that carried [item]. In alias mode the item's aliases are
     * highlighted in the request and response editors.
     */
    private fun showResultItem(run: BatchRun, item: BatchResultItem, switchToMessage: Boolean) {
        val rowIdx = this.attacks.indexOfFirst { it.run === run && it.part == item.part }
        if (rowIdx < 0) return
        selectHistoryRow(rowIdx)
        if (run.mode == BatchMode.ALIAS) setMessageSearch("op${item.localIndex}_")
        if (switchToMessage) this.detailTabs.selectedComponent = this.historyRequestViewer
    }

    private fun setMessageSearch(expression: String) {
        this.historyRequestViewer.request.setSearchExpression(expression)
        this.historyRequestViewer.response.setSearchExpression(expression)
    }

    private fun historyTableSelectionListener(rowIndex: Int) {
        if (rowIndex !in this.attacks.indices) return
        val entry = this.attacks[rowIndex]
        this.selected = entry
        // Drop any highlight left over from a previously selected result item.
        setMessageSearch("")
        this.historyRequestViewer.request.request = entry.req
        this.historyRequestViewer.response.response = entry.resp
        this.resultsPanel.showRun(entry.run, hasHistoryRow = true)
    }

    fun loadFromRequest(req: HttpRequest) {
        this.url = req.url()
        this.request = req
        this.payloadsPanel.refreshFromRequest(req)
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
        try {
            this.payloadsPanel.refreshFromRequest(this.request)
        } catch (e: Exception) {
            Logger.error("Failed refreshing Batch Queries variables on project load: ${e.message}")
        }
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
