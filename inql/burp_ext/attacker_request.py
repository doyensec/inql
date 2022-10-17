from __future__ import print_function

import platform

from inql.burp_ext.contextual import SendMenuItem

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import logging

from burp import IMessageEditorController
from java.awt.event import ActionListener
from java.util import ArrayList
from javax.swing import JPanel, JSplitPane, JLabel, JComboBox, JButton, BoxLayout, Box, JTextField, JTable, JScrollPane, JTabbedPane, BorderFactory, UIManager, SwingUtilities
from javax.swing.table import AbstractTableModel
from threading import Lock
from java.io import PrintWriter;
from java.awt import BorderLayout, FlowLayout, Dimension
import sys
if sys.version_info.major == 3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse
from threading import Thread
import datetime


class RequestData:
    def __init__(self, host, path, start, end):
        self.date = datetime.datetime.now().strftime("%H:%M:%S %d %b %Y")
        self.host = host
        self.path = path
        self.start = start
        self.end = end

class InitiateAttack(ActionListener):
    def __init__(self, callbacks, helpers, editor):
        self.callbacks = callbacks
        self.helpers = helpers
        self.editor = editor

    def actionPerformed(self, event):
        # Send the request in a new thread to prevent locking up GUI
        t = Thread(
            target=self.send,
            args=[self.editor.url, self.editor.request]
        )
        t.daemon = True
        t.start()

    def send(self, url, request):
        u = urlparse(url)
        host = u.netloc
        port = u.port or (443 if u.scheme == 'https' else 80)

        useHttps = (u.port == 443 or u.scheme == 'https')
        httpService = self.helpers.buildHttpService(host, port, useHttps)

        # note that we're not sending path to the Attacker tab, but we need it for log table,
        # so it gets extracted from the request bytes
        path = self.helpers.analyzeRequest(httpService, request).getUrl().getPath()

        self.editor.requests[hash(str(request))] = RequestData(
            host=host, path=path, start="", end="")

        response = self.callbacks.makeHttpRequest(httpService, request).response

        info = self.helpers.analyzeResponse(response)

        logging.info("sent the request and received the response with a status code: %s" % info.statusCode)

class RequestEditorComponent(IMessageEditorController):
    def __init__(self, callbacks, helpers):
        self.analyzeRequest = helpers.analyzeRequest
        self.request_editor = callbacks.createMessageEditor(self, True)
        self._menu_item = SendMenuItem(callbacks, self.send_to, "Attacker (new)")
        self.send_action = InitiateAttack(callbacks, helpers, self)
        self.url_component = JTextField()

        # hash table of the sent requests
        # hash tables are thread-safe in Jython: https://jython.readthedocs.io/en/latest/Concurrency/
        self.requests = {}

    @property
    def url(self):
        return self.url_component.text

    @url.setter
    def url(self, text):
        self.url_component.text = str(text)

    @property
    def request(self):
        return self.request_editor.getMessage()

    @request.setter
    def request(self, data):
        self.request_editor.setMessage(data, True)

    def send_to(self, rr):
        """Action that gets fired upon selecting "Send to Attacker" from the context menu."""
        self.url = rr.httpService
        self.request = rr.request

    def render(self):
        urlpane = JPanel(BorderLayout(5, 5), border = BorderFactory.createEmptyBorder(5, 5, 5, 5))
        urlpane.add(JLabel("Target: "), BorderLayout.WEST)
        urlpane.add(self.url_component, BorderLayout.CENTER)

        send_button = JButton(text="Send")
        send_button.addActionListener(self.send_action)

        urlpane.add(send_button, BorderLayout.EAST)

        panel = JPanel(BorderLayout(5, 5))
        panel.add(urlpane, BorderLayout.NORTH)
        panel.add(self.request_editor.component, BorderLayout.CENTER)

        return panel

    def getHttpService(self):
        return None

    def getRequest(self):
        return None

    def getResponse(self):
        return None

class AttackerRequest:
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._analyze = helpers.analyzeRequest

        self.bottomleft = RequestEditorComponent(self._callbacks, self._helpers)

        self.fix = callbacks.customizeUiComponent

    @property
    def requests(self):
        return self.bottomleft.requests

    def render(self):
        # Payloads
        labels = JPanel()
        labels.setLayout(BoxLayout(labels, BoxLayout.Y_AXIS))
        labels.add(JLabel("Payload set: "))
        labels.add(JLabel("Payload data: "))

        inputs = JPanel()
        inputs.setLayout(BoxLayout(inputs, BoxLayout.Y_AXIS))
        inputs.add(JComboBox(["1", "2", "3"]))
        inputs.add(JButton(text="Upload payload"))

        payloads = JPanel()
        payloads.add(labels)
        payloads.add(inputs)

        # Buttons
        buttons = JPanel()
        buttons.setLayout(BoxLayout(buttons, BoxLayout.Y_AXIS))
        buttons.add(JButton(text="Add $"))
        buttons.add(JButton(text="Clear $"))

        # Top-Left panel
        topleft = JPanel(BorderLayout(5, 5), border = BorderFactory.createEmptyBorder(5,5,5,5))
        topleft.add(payloads, BorderLayout.CENTER)
        topleft.add(buttons, BorderLayout.EAST)

        # This will be a left pane under "InQL Attacker" tab
        pane = JPanel(BorderLayout(5, 5))
        pane.add(topleft, BorderLayout.NORTH)
        pane.add(self.bottomleft.render(), BorderLayout.CENTER)
        self.fix(pane)
        return pane
