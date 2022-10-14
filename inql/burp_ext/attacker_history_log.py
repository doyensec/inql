from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)


from burp import IHttpListener
from java.util import ArrayList
from javax.swing import JTable, JScrollPane
from javax.swing.table import AbstractTableModel
from threading import Lock
from java.io import PrintWriter;

class AttackerHistoryLog(AbstractTableModel, IHttpListener):
    def __init__(self, callbacks, viewer):
        self._getToolName = callbacks.getToolName
        self.viewer = viewer

        self._lock = Lock()
        self.db = ArrayList()

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)

    def render(self):
        return JScrollPane(AttackHistoryLogTable(model=self))

    def getRowCount(self):
        try:
            return self.db.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, col):
        if col == 0:
            return "Tool"
        if col == 1:
            return "URL"
        return ""

    def getValueAt(self, row, col):
        entry = self.db.get(row)
        if col == 0:
            return self._getToolName(entry._tool)
        if col == 1:
            return entry.toString()
        return ""

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self._stdout.println(
                ("HTTP request to " if messageIsRequest else "HTTP response from ") +
                messageInfo.getHttpService().toString() +
                " [" + self._getToolName(toolFlag) + "]")


class AttackHistoryLogTable(JTable):
    """Custom JTable wrapper with row selection support."""
    def __init__(self, model):
        self.log = model
        self.setModel(model)

    def changeSelection(self, row, col, toggle, extend):
        entry = self.log.db.get(row)
        self.log.viewer.response.setMessage(entry.rr.getRequest(), False)
        self.log.viewer.response.setMessage(entry.rr.getResponse(), False)
        self.log.current = entry.rr

        JTable.changeSelection(self, row, col, toggle, extend)


class AttackLogEntry:
    def __init__(self, tool, requestResponse, url):
        self.tool = tool
        self.rr = requestResponse
        self.url = url