from __future__ import print_function

import platform

from inql.burp_ext.contextual import SendMenuItem

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
    def __init__(self, callbacks, helpers):
        self._helpers = helpers
        self._analyze = helpers.analyzeRequest

        self.url = JTextField()

        self.request_editor = callbacks.createMessageEditor(self, True)
        self.fix = callbacks.customizeUiComponent

        self._menu_item = SendMenuItem(callbacks, self.send_to, "Attacker (new)")

    def _get_url(self, rr):
        """Get URL. Should be as easy as helpers.analyzeRequest(request).getUrl(), but that doesn't work for some reason."""
        http = rr.httpService

        protocol = http.protocol
        host = http.host
        port = http.port

        if (port == 80 and protocol == 'http') or (port == 443 and protocol == 'https'):
            url = "%s://%s" % (protocol, host)
        else:
            url = "%s://%s:%s" % (protocol, host, port)

        return url

    def send_to(self, rr=None):
        url = self._get_url(rr)
        request = rr.request

        self.url.text = url
        self.request_editor.setMessage(request, True)

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
        self.fix(self.url)
        urlpane.add(self.url, BorderLayout.CENTER)
        urlpane.add(JButton(text="Send"), BorderLayout.EAST)
        self.fix(urlpane)

        bottomleft = JPanel(BorderLayout(5, 5))
        bottomleft.add(urlpane, BorderLayout.NORTH)
        self.editor = self.request_editor.component
        bottomleft.add(self.editor, BorderLayout.CENTER)
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