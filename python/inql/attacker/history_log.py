# coding: utf-8
from threading import Lock

from burp import IHttpListener

from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JScrollPane, JTable
from javax.swing.table import AbstractTableModel

from ..globals import callbacks, helpers


class AttackerHistoryLog(AbstractTableModel, IHttpListener):
    def __init__(self, viewer, editor):
        self._getToolName = callbacks.getToolName
        self.viewer = viewer
        self.editor = editor
        self.EXTENDER_FLAG = callbacks.TOOL_EXTENDER

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
        return 7

    def getColumnName(self, col):
        return [
            "Date",
            "Host",
            "Path",
            "Status",
            "Length",
            "From",
            "To"
        ][col]

    def getValueAt(self, row, col):
        entry = self.db.get(row)
        if col == 0:
            return entry.date
        if col == 1:
            return entry.host
        if col == 2:
            return entry.path
        if col == 3:
            return entry.status
        if col == 4:
            return entry.length
        if col == 5:
            return entry.start
        if col == 6:
            return entry.end
        raise Exception("Unexpected column index: %s" % col)

    def processHttpMessage(self, toolFlag, isRequest, rr):
        if (not isRequest) and (toolFlag == self.EXTENDER_FLAG):
            request = rr.request
            hashid = hash(str(request))
            if hashid in self.editor.requests:
                data = self.editor.requests.pop(hashid)

                info = helpers.analyzeResponse(rr.response)

                status = info.getStatusCode()
                length = len(rr.response) - info.getBodyOffset()

                # save memory by offloading requests and responses to disk
                rr_offloaded = callbacks.saveBuffersToTempFiles(rr)
                entry = AttackLogEntry(data, status, length, rr_offloaded)

                # Java's Arraylist isn't thread safe
                self._lock.acquire()
                self.db.add(entry)
                self.fireTableRowsInserted(self.getRowCount(), self.getRowCount())
                self._lock.release()



class AttackHistoryLogTable(JTable):
    """Custom JTable wrapper with row selection support."""
    def __init__(self, model):
        self.log = model
        self.setModel(model)

    def changeSelection(self, row, col, toggle, extend):
        entry = self.log.db.get(row)
        self.log.viewer.request_editor.setMessage(entry.rr.getRequest(), False)
        self.log.viewer.response_editor.setMessage(entry.rr.getResponse(), False)
        self.log.current = entry.rr

        JTable.changeSelection(self, row, col, toggle, extend)


class AttackLogEntry(object):
    def __init__(self, data, status, length, rr):
        self.date = data.date
        self.host = data.host
        self.path = data.path
        self.status = status
        self.length = length
        self.start = data.start
        self.end = data.end
        self.rr = rr
