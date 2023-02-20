import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.lang import Object as JavaObject, String as JavaString, Short as JavaShort, Long as JavaLong
from java.util import ArrayList as JavaArrayList
from javax.swing.table import AbstractTableModel
from javax.swing import JPanel, BoxLayout, JSplitPane, JScrollPane, JTabbedPane, BorderFactory, JLabel, JButton, JComboBox, JCheckBox, JTextField
from java.awt import Color, FlowLayout

class TimerPanel:
    def __init__(self,
                 logtable_factory=None,
                 external_filter_action_listener=None,
                 external_start_button_action_listener=None,
                 external_stop_button_action_listener=None,
                 external_clear_button_action_listener=None,
                 tools_keys=None):
        self.this = JPanel()

        if tools_keys is None:
            tools_keys = []

        self.external_start_button_action_listener = external_start_button_action_listener
        self.external_stop_button_action_listener = external_stop_button_action_listener
        self.external_clear_button_action_listener = external_clear_button_action_listener


        self.this.setLayout(BoxLayout(self.this, BoxLayout.Y_AXIS))

        # main split pane
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTableModel = LogTableModel()
        self.logTableModel = logTableModel
        if logtable_factory is not None:
            logTable = logtable_factory(logTableModel)
        else:
            # XXX: create a generic logtable that works even without burp to made it work standalone
            raise ValueError("logtable_factory cannot be none")
        scrollPane = JScrollPane(logTable)
        splitPane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        tabs.setBorder(BorderFactory.createLineBorder(Color.black))
        tabs.addTab("Request", logTable.getRequestViewer().getComponent())
        tabs.addTab("Response", logTable.getResponseViewer().getComponent())
        splitPane.setRightComponent(tabs)

        # top control panel
        controlPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        toolLabel = JLabel("Select tool: ")
        controlPanel.add(toolLabel)


        tools = JavaArrayList(tools_keys)
        toolList = JComboBox(tools)
        toolList.addActionListener(external_filter_action_listener)
        controlPanel.add(toolList)

        startButton = JButton("Start")
        self.startButton = startButton
        controlPanel.add(startButton)
        stopButton = JButton("Stop")
        self.stopButton = stopButton
        controlPanel.add(stopButton)
        clearButton = JButton("Clear")
        self.clearButton = clearButton
        startButton.setEnabled(False)
        controlPanel.add(clearButton)
        scopeLabel = JLabel("In-scope items only?")
        controlPanel.add(scopeLabel)
        scopeCheckBox = JCheckBox()
        self.scopeCheckBox = scopeCheckBox
        controlPanel.add(scopeCheckBox)
        filterLabel = JLabel("Filter Query:")
        controlPanel.add(filterLabel)
        queryFilterText = JTextField(40)
        self.queryFilterText = queryFilterText
        controlPanel.add(queryFilterText)

        startButton.addActionListener(self.start_button_action_listener)

        stopButton.addActionListener(self.stop_button_action_listener)

        clearButton.addActionListener(self.clear_button_action_listener)

        controlPanel.setAlignmentX(0)
        self.this.add(controlPanel)
        self.this.add(splitPane)

    def getTabCaption(self):
        return "Request Timer"
    
    def getUiComponent(self):
        return self.this

    def getLogTableModel(self):
        return self.logTableModel
    

    def getQueryFilterText(self):
        return self.queryFilterText.getText()
    

    def isScopeSelected(self):
        return self.scopeCheckBox.isSelected()

    def start_button_action_listener(self, e):
        self.external_start_button_action_listener(e)
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def stop_button_action_listener(self, e):
        self.external_stop_button_action_listener(e)
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    def clear_button_action_listener(self, e):
        self.external_clear_button_action_listener(e)
        self.logTableModel.getLogArray().clear()
        self.logTableModel.fireTableDataChanged()


class Log:
    def __init__(self, timestamp, tool, requestResponse, url, status, operationName, time):
        self.timestamp = timestamp
        self.tool = tool
        self.requestResponse = requestResponse
        self.url = url
        self.time = time
        self.status = status
        self.operationName = operationName


class LogTableModel(AbstractTableModel):
    def __init__(self):
        self.logArray = JavaArrayList()
        self.names = ["Timestamp", "Tool", "Request URL", "Operation Name", "Response Time (ms)", "HTTP Status"]
        self.classes = [JavaString, JavaString, JavaString, JavaString, JavaLong, JavaShort]

    def getRowCount(self):
        return len(self.logArray)

    def getColumnCount(self):
        return len(self.names)

    def getColumnName(self, columnIndex):
        if columnIndex < 0 or columnIndex > len(self.names):
            return ""
        return self.names[columnIndex]

    def getColumnClass(self, columnIndex):
        if columnIndex < 0 or columnIndex > len(self.classes):
            return JavaObject.getClass()
        return self.classes[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        entry = self.logArray[rowIndex]
        if columnIndex == 0:
            return entry.timestamp
        elif columnIndex == 1:
            return entry.tool
        elif columnIndex == 2:
            return entry.url.toString()
        elif columnIndex == 3:
            return entry.operationName
        elif columnIndex == 4:
            return entry.time
        elif columnIndex == 5:
            return entry.status
        else:
            return ""

    def getLogArray(self):
        return self.logArray