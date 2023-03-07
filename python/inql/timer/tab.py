# coding: utf-8
import json

from burp import IBurpExtenderCallbacks, IHttpListener, IMessageEditorController, ITab

from java.lang import System
from java.time import LocalDateTime
from java.util import HashMap
from javax.swing import JTable
from org.python.modules import synchronize

from ..globals import callbacks, helpers
from ..timer.panel import Log, TimerPanel
from ..utils.graphql import is_query
from ..utils.ui import raw_editor_obsolete

# TODO: Review the file once other functionality has been stabilized
# pylint: skip-file

class TimerTab(ITab, IHttpListener):
    def __init__(self):
        self.isRunning = True
        self.toolFilter = 0
        self.reqResMap = HashMap()
        callbacks.registerHttpListener(self);
        self.panel = TimerPanel(
            logtable_factory=LogTable,
            external_clear_button_action_listener=lambda e: self.getReqResMap().clear(),
            external_start_button_action_listener=lambda e: self.setRunning(True),
            external_stop_button_action_listener=lambda e: self.setRunning(False),
            external_filter_action_listener=self.filter_action_listener,
            tools_keys=["All", "Proxy", "Intruder", "Scanner", "Repeater"]
        )

    def getTabCaption(self):
        """
        Override ITab method
        :return: tab name
        """
        return "InQL Timer"

    def getUiComponent(self):
        """
        Override ITab method
        :return: Tab UI Component
        """
        callbacks.customizeUiComponent(self.panel.this)
        return self.panel.this

    def filter_action_listener(self, e):
        tool = e.getSource().getSelectedItem()
        if tool == "All":
            self.setToolFilter(0)
        elif tool == "Proxy":
            self.setToolFilter(IBurpExtenderCallbacks.TOOL_PROXY)
        elif tool == "Intruder":
            self.setToolFilter(IBurpExtenderCallbacks.TOOL_INTRUDER)
        elif tool == "Scanner":
            self.setToolFilter(IBurpExtenderCallbacks.TOOL_SCANNER)
        elif tool == "Repeater":
            self.setToolFilter(IBurpExtenderCallbacks.TOOL_REPEATER)
        else:
            raise RuntimeError("Unknown tool: %s" % tool)

    def setRunning(self, running):
        self.isRunning = running

    def setToolFilter(self, toolFilter):
        self.toolFilter = toolFilter

    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):

        if self.isRunning:
            if self.toolFilter == 0 or self.toolFilter == toolFlag:
                messageInfo = helpers.analyzeRequest(requestResponse)
                url = messageInfo.getUrl()
                requestBody = requestResponse.getRequest()[messageInfo.getBodyOffset():].tostring()
                if not is_query(requestBody):
                    return # exit early

                qobj = json.loads(requestBody)
                if type(qobj) != dict:
                    return

                queryBody = ""
                operationName = ""
                if 'query' in qobj:
                    queryBody = qobj['query']
                if 'operationName' in qobj:
                    operationName = qobj['operationName']
                if messageIsRequest:
                    self.reqResMap.put(url, System.currentTimeMillis())
                elif self.reqResMap.containsKey(url):
                    time = System.currentTimeMillis() - self.reqResMap.get(url)
                    self.reqResMap.remove(url)
                    # create a new log entry with the message details
                    synchronize.apply_synchronized(self.panel.getLogTableModel().getLogArray(),
                                                   self.syncProcessHttpMessage,
                                                   (toolFlag, requestResponse, time, queryBody, operationName))

    def syncProcessHttpMessage(self, toolFlag, messageInfo, time, queryBody, operationName):
        row = self.panel.getLogTableModel().getLogArray().size()
        # Log all requests - the default
        if not self.panel.getQueryFilterText() and not self.panel.isScopeSelected():
            self.addLog(messageInfo, toolFlag, time, row, operationName)
        # Log filter URL requests
        elif not self.panel.isScopeSelected() and self.panel.getQueryFilterText() and \
            self.panel.getQueryFilterText() in queryBody:
            self.addLog(messageInfo, toolFlag, time, row, operationName)
        # Log in-scope requests
        elif self.panel.isScopeSelected() and not self.panel.getQueryFilterText() and \
              callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl()):
            self.addLog(messageInfo, toolFlag, time, row, operationName)
        # Log in-scope requests and filter
        elif self.panel.isScopeSelected() and self.panel.getQueryFilterText() and \
                callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl()) and \
                self.panel.getQueryFilterText() in queryBody:
            self.addLog(messageInfo, toolFlag, time, row, operationName)

    def addLog(self, messageInfo, toolFlag, time, row, operationName):

        self.panel.getLogTableModel().getLogArray().add(Log(LocalDateTime.now().toString(),
                                                           callbacks.getToolName(toolFlag),
                                                           callbacks.saveBuffersToTempFiles(messageInfo),
                                                           helpers.analyzeRequest(messageInfo).getUrl(),
                                                           helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode(),
                                                           operationName,
                                                           time))
        self.panel.getLogTableModel().fireTableRowsInserted(row, row)

    def getReqResMap(self):
        return self.reqResMap

class LogTable(JTable, IMessageEditorController):
    def __init__(self, logTableModel):
        JTable.__init__(self, logTableModel)
        self.logTableModel = logTableModel
        self.requestViewer = callbacks.createMessageEditor(self, False)
        self.responseViewer = callbacks.createMessageEditor(self, False)
        self.requestViewer = raw_editor_obsolete(self, False)
        self.responseViewer = raw_editor_obsolete(self, False)
        self.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.getColumnModel().getColumn(0).setMinWidth(200)
        self.getColumnModel().getColumn(1).setMinWidth(100)
        self.getColumnModel().getColumn(2).setPreferredWidth(1000)
        self.getColumnModel().getColumn(3).setMinWidth(100)
        self.getColumnModel().getColumn(4).setMinWidth(150)
        self.getColumnModel().getColumn(5).setMinWidth(100)
        self.setAutoCreateRowSorter(True)
        self.currentlyDisplayedItem = None

    def getRequest(self):
        return self.currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self.currentlyDisplayedItem.getResponse()

    def getHttpService(self):
        return self.currentlyDisplayedItem.getHttpService()

    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self.logTableModel.getLogArray().get(self.convertRowIndexToModel(row))
        self.requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
        self.responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)
        self.currentlyDisplayedItem = logEntry.requestResponse

        self.super__changeSelection(row, col, toggle, extend)

    def getRequestViewer(self):
        return self.requestViewer

    def getResponseViewer(self):

        return self.responseViewer
