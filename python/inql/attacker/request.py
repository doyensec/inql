# coding: utf-8
import datetime
import json
import re
from threading import Thread

from urlparse import urlparse

from burp import IMessageEditorController

from java.awt import BorderLayout
from java.awt.event import ActionListener
from javax.swing import JLabel, JPanel, JTextField

from ..globals import app, callbacks, helpers
from ..logger import log
from ..menu.contextual import SendMenuItem
from ..utils.pyswing import button, multiline_label, panel
from ..utils.ui import raw_editor_obsolete


class RequestData(object):
    def __init__(self, host, path, start, end):
        self.date = datetime.datetime.now().strftime("%H:%M:%S %d %b %Y")
        self.host = host
        self.path = path
        self.start = start
        self.end = end

class InitiateAttack(ActionListener):
    def __init__(self, editor):
        self.editor = editor

    def generate_attack_request(self):
        info = helpers.analyzeRequest(self.editor.request)
        headers = info.getHeaders()
        raw = helpers.bytesToString(self.editor.request[info.getBodyOffset():])
        body = str(raw).replace('\\r', '').replace('\\n', ' ').replace('\\t', '')
        parsed = json.loads(body)
        if isinstance(parsed, list):
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
                re.match(r'(.*?)\$\[(INT):(\d+:\d+)\](.*)', pfx) or
                # $[FILE:path] and $[FILE:path:first:last]
                re.match(r'(.*?)\$\[(FILE):([^:]+(?::\d+:\d+)?)\](.*)', pfx)
            )
            if not match:
                prefix = prefix + pfx + '{'
                suffix = '}' + sfx + suffix
                continue

            # found the placeholder
            lead, verb, args, rest = match.groups()
            args = args.split(':')
            log.debug("lead: %s, verb: %s, args: %s, rest: %s" % (lead, verb, args, rest))

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

            log.debug("attack query: %s" % attack)
            body = json.dumps({'query': attack})

            return helpers.buildHttpMessage(headers, helpers.stringToBytes(body)), start, end

    def actionPerformed(self, _):
        # Send the request in a new thread to prevent locking up GUI
        log.debug("Initiate attack handler fired")
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
        httpService = helpers.buildHttpService(host, port, useHttps)

        # note that we're not sending path to the Attacker tab, but we need it for log table,
        # so it gets extracted from the request bytes
        path = helpers.analyzeRequest(httpService, request).getUrl().getPath()

        self.editor.requests[hash(str(request))] = RequestData(
            host=host, path=path, start=start, end=end)

        response = callbacks.makeHttpRequest(httpService, request).response

        info = helpers.analyzeResponse(response)

        log.info("sent the request and received the response with a status code: %s" % info.statusCode)

class RequestEditorComponent(IMessageEditorController):
    def __init__(self):
        self.analyzeRequest = helpers.analyzeRequest
        self.request_editor = raw_editor_obsolete(self, True)
        #self._configure_menu_item("Attacker")
        self.send_handler = InitiateAttack(self)
        self.url_component = JTextField()

        # hash table of the sent requests
        # hash tables are thread-safe in Jython: https://jython.readthedocs.io/en/latest/Concurrency/
        self.requests = {}

    def _configure_menu_item(self, label):
        """If a SendMenuItem has been registered, reuse it. Otherwise create a new menu item."""
        for handler in callbacks.getContextMenuFactories():
            if isinstance(handler, SendMenuItem) and handler.label == label:
                handler.burp_handler = self.send_to
                break
        else:
            SendMenuItem(label, burp_handler=self.send_to)

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

    def send_to(self, url, request):
        """Action that gets fired upon selecting "Send to Attacker" from the context menu."""
        log.debug("Received the request to prepare the Attacker")
        self.url, self.request = url, request.toString()
        log.debug("Attacker received a request: %s and here's contents: %s", self.url, self.request)

        log.debug("requestFocusInWindow: burp to inql")
        app.main_tab.panel.getParent().setSelectedComponent(app.main_tab.panel)
        log.debug("requestFocusInWindow: main tab to attacker")
        app.main_tab.pane.setSelectedComponent(app.attacker_tab)
        self.url_component.requestFocusInWindow()

    def render(self):
        urlpane = panel()
        urlpane.add(JLabel("Target: "), BorderLayout.WEST)
        urlpane.add(self.url_component, BorderLayout.CENTER)

        send_button = button("Send", self.send_handler)
        urlpane.add(send_button, BorderLayout.EAST)

        top_panel = panel()
        top_panel.add(urlpane, BorderLayout.NORTH)
        top_panel.add(self.request_editor.component, BorderLayout.CENTER)

        return top_panel

    def getHttpService(self):
        return None

    def getRequest(self):
        return None

    def getResponse(self):
        return None

class AttackerRequest(object):
    def __init__(self):
        self._analyze = helpers.analyzeRequest

        self.bottomleft = RequestEditorComponent()

        self.fix = callbacks.customizeUiComponent

    @property
    def requests(self):
        return self.bottomleft.requests

    def render(self):
        # Payloads
        doc = multiline_label("""
Supported placeholders:

    $[INT:first:last] - first and last are integers, both are included in the range
    $[FILE:path:first:last] - absolute path and the (optional) range of lines (first line is 1 not 0)

Current limitations: only one placeholder, no variables.
""")

        # This will be a left pane under "InQL Attacker" tab
        pane = JPanel(BorderLayout(5, 5))
        pane.add(doc, BorderLayout.NORTH)
        pane.add(self.bottomleft.render(), BorderLayout.CENTER)
        self.fix(pane)
        return pane

    def send_to(self, url, request):
        self.bottomleft.send_to(url, request)
