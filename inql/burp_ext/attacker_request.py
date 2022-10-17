from __future__ import print_function

import platform

import json
import re
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

    def generate_attack_request(self):
        info = self.helpers.analyzeRequest(self.editor.request)
        headers = info.getHeaders()
        raw = self.helpers.bytesToString(self.editor.request[info.getBodyOffset():])
        body = str(raw).replace('\\r', '').replace('\\n', ' ').replace('\\t', '')
        parsed = json.loads(body)
        if type(parsed) == list:
            parsed = parsed[0]
        query = parsed['query']

        prefix, suffix = "", ""
        while True:
            # FIXME: whitespace inbetween will break the regex!

            # look until first {
            match = re.match('([^{]*?){(.+)}([^}]*?)', query)
            if not match:
                break
            pfx, query, sfx = match.groups()

            # look for a placeholder
            match = (
                # $[INT:first:last]
                re.match('(.*?)\$\[(INT):(\d+:\d+)\](.*)', pfx) or
                # $[FILE:path] and $[FILE:path:first:last]
                re.match('(.*?)\$\[(FILE):([^:]+(?::\d+:\d+)?)\](.*)', pfx)
            )
            if not match:
                prefix = prefix + pfx + '{'
                suffix = '}' + sfx + suffix
                continue

            # found the placeholder
            lead, verb, args, rest = match.groups()
            args = args.split(':')
            logging.debug("lead: %s, verb: %s, args: %s, rest: %s" % (lead, verb, args, rest))

            exploit = ""
            if verb == 'INT':
                # $[INT:first:last]
                start, end = args
                for n, item in enumerate(range(int(start), int(end)+1)):
                    exploit += 'op%s: %s%s%s{%s}%s' % (n+1, lead, item, rest, query, sfx)
            if verb == 'FILE':
                # $[FILE:path] and $[FILE:path:first:last]
                path = args[0]
                with open(path) as f:
                    items = f.read().splitlines()
                if len(args) == 3:
                    start, end = int(args[1]), int(args[2])
                else:
                    start, end = 1, len(items)

                for n, item in enumerate(items[start-1: end]):
                    exploit += 'op%s: %s%s%s{%s}%s' % (n+1, lead, item, rest, query, sfx)

            #build the query
            attack = prefix + exploit + suffix

            logging.debug("attack query: %s" % attack)
            body = json.dumps({'query': attack})

            return self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body)), start, end

    def actionPerformed(self, event):
        # Send the request in a new thread to prevent locking up GUI
        url = self.editor.url
        attack_request, start, end = self.generate_attack_request()
        t = Thread(
            target=self.send,
            args=[url, attack_request, start, end]
        )
        t.daemon = True
        t.start()

    def send(self, url, request, start, end):
        u = urlparse(url)
        host = u.netloc
        port = u.port or (443 if u.scheme == 'https' else 80)

        useHttps = (u.port == 443 or u.scheme == 'https')
        httpService = self.helpers.buildHttpService(host, port, useHttps)

        # note that we're not sending path to the Attacker tab, but we need it for log table,
        # so it gets extracted from the request bytes
        path = self.helpers.analyzeRequest(httpService, request).getUrl().getPath()

        self.editor.requests[hash(str(request))] = RequestData(
            host=host, path=path, start=start, end=end)

        response = self.callbacks.makeHttpRequest(httpService, request).response

        info = self.helpers.analyzeResponse(response)

        logging.info("sent the request and received the response with a status code: %s" % info.statusCode)

class RequestEditorComponent(IMessageEditorController):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.analyzeRequest = helpers.analyzeRequest
        self.request_editor = callbacks.createMessageEditor(self, True)
        self._configure_menu_item("Attacker")
        self.send_action = InitiateAttack(callbacks, helpers, self)
        self.url_component = JTextField()

        # hash table of the sent requests
        # hash tables are thread-safe in Jython: https://jython.readthedocs.io/en/latest/Concurrency/
        self.requests = {}

    def _configure_menu_item(self, label):
        """If a SendMenuItem has been registered, reuse it. Otherwise create a new menu item."""
        for handler in self.callbacks.getContextMenuFactories():
            if type(handler) is SendMenuItem and handler.label == label:
                handler.burp_handler = self.send_to
                break
        else:
            return SendMenuItem(self.callbacks, label, burp_handler=self.send_to)

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

    def send_to(self, first, second=None, inql=False):
        """Action that gets fired upon selecting "Send to Attacker" from the context menu."""
        if inql:
            # Received a mouse click from InQL Scanner tab
            self.url, self.request = first, second
        else:
            # Received a mouse click from Burp tabs (Repeater, Intruder)
            rr = first

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
        doc = JPanel(border = BorderFactory.createEmptyBorder(10, 10, 10, 10))
        doc.setLayout(BoxLayout(doc, BoxLayout.Y_AXIS))
        doc.add(JLabel("Supported placeholders:", border = BorderFactory.createEmptyBorder(10, 0, 5, 0)))
        doc.add(JLabel("$[INT:first:last] - first and last are integers, both are included in the range", border = BorderFactory.createEmptyBorder(5, 0, 5, 0)))
        doc.add(JLabel("$[FILE:path:first:last] - absolute path and the (optional) range of lines (first line is 1 not 0)", border = BorderFactory.createEmptyBorder(5, 0, 5, 0)))
        doc.add(JLabel("Current limitations: only one placeholder, no variables", border = BorderFactory.createEmptyBorder(5, 0, 5, 0)))

        # This will be a left pane under "InQL Attacker" tab
        pane = JPanel(BorderLayout(5, 5))
        pane.add(doc, BorderLayout.NORTH)
        pane.add(self.bottomleft.render(), BorderLayout.CENTER)
        self.fix(pane)
        return pane
