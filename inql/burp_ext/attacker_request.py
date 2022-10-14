from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from burp import IMessageEditorController
from java.util import ArrayList
from javax.swing import JPanel, JSplitPane, JLabel, JComboBox, JButton, BoxLayout, Box, JTextField, JTable, JScrollPane, JTabbedPane, BorderFactory, UIManager, SwingUtilities
from javax.swing.table import AbstractTableModel
from threading import Lock
from java.io import PrintWriter;
from java.awt import BorderLayout, FlowLayout, Dimension

class AttackerRequest(IMessageEditorController):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self.request_editor = self._callbacks.createMessageEditor(self, True).getComponent()
        self.fix = self._callbacks.customizeUiComponent

    def render(self):
        # Payloads
        labels = JPanel()
        labels.setLayout(BoxLayout(labels, BoxLayout.Y_AXIS))
        labels.add(JLabel("Payload set: "))
        labels.add(JLabel("Payload data: "))
        self.fix(labels)

        inputs = JPanel()
        inputs.setLayout(BoxLayout(inputs, BoxLayout.Y_AXIS))
        inputs.add(JComboBox(["1", "2", "3"]))
        inputs.add(JButton(text="Upload payload"))
        self.fix(inputs)

        payloads = JPanel()
        payloads.add(labels)
        payloads.add(inputs)
        self.fix(payloads)

        # Buttons
        buttons = JPanel()
        buttons.setLayout(BoxLayout(buttons, BoxLayout.Y_AXIS))
        buttons.add(JButton(text="Add $"))
        buttons.add(JButton(text="Clear $"))
        self.fix(buttons)

        # Top-Left panel
        topleft = JPanel(BorderLayout(5, 5), border = BorderFactory.createEmptyBorder(5,5,5,5))
        topleft.add(payloads, BorderLayout.CENTER)
        topleft.add(buttons, BorderLayout.EAST)
        self.fix(topleft)

        # Bottom-Left panel (editor)
        urlpane = JPanel(BorderLayout(5, 5), border = BorderFactory.createEmptyBorder(5, 5, 5, 5))
        urlpane.add(JLabel("Target: "), BorderLayout.WEST)
        url = JTextField()
        self.fix(url)
        urlpane.add(url, BorderLayout.CENTER)
        urlpane.add(JButton(text="Send"), BorderLayout.EAST)
        self.fix(urlpane)

        bottomleft = JPanel(BorderLayout(5, 5))
        bottomleft.add(urlpane, BorderLayout.NORTH)
        tabs = JTabbedPane()
        editor = self.request_editor
        tabs.addTab("Request", editor)
        bottomleft.add(tabs, BorderLayout.CENTER)
        self.fix(bottomleft)

        # This will be a left pane under "InQL Attacker" tab
        pane = JPanel(BorderLayout(5, 5))
        pane.add(topleft, BorderLayout.NORTH)
        pane.add(bottomleft, BorderLayout.CENTER)
        self.fix(pane)
        return pane

    def getHttpService(self):
        return None
        #return self.current.getHttpService()

    def getRequest(self):
        return None
        #return self.current.getRequest()

    def getResponse(self):
        return None
        #return self.current.getResponse()