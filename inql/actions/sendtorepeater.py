import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import ActionListener
from javax.swing import JMenuItem
from org.python.core.util import StringUtil

from burp import IProxyListener, IContextMenuFactory

from inql.constants import *
from inql.utils import string_join, override_headers


class RepeaterSenderAction(IProxyListener, ActionListener, IContextMenuFactory):
    def __init__(self, callbacks, helpers, text, overrideheaders):
        self.requests = {}
        self._helpers = helpers
        self._callbacks = callbacks
        self.menuitem = JMenuItem(text)
        self._burp_menuitem = JMenuItem("inql: %s" % text)
        self._callbacks.registerProxyListener(self)
        self.menuitem.addActionListener(self)
        self.menuitem.setEnabled(False)
        self._burp_menuitem.addActionListener(self)
        self._burp_menuitem.setEnabled(False)
        self._index = 0
        self._host = None
        self._payload = None
        self._fname = None
        for r in self._callbacks.getProxyHistory():
            self._process_request(self._helpers.analyzeRequest(r), r.getRequest())
        self._callbacks.registerContextMenuFactory(self)
        self._overrideheaders = overrideheaders

    def processProxyMessage(self, messageIsRequest, message):
        """
        Implements IProxyListener method

        :param messageIsRequest: True if BURP Message is a request
        :param message: message content
        :return: None
        """
        if messageIsRequest:
            self._process_request(self._helpers.analyzeRequest(message.getMessageInfo()),
                                  message.getMessageInfo().getRequest())

    def _process_request(self, reqinfo, reqbody):
        """
        Process request and extract key values

        :param reqinfo:
        :param reqbody:
        :return:
        """
        url = str(reqinfo.getUrl())
        if any([url.endswith(x) for x in URLS]):
            for h in reqinfo.getHeaders():
                if h.lower().startswith("host:"):
                    domain = h[5:].strip()

            method = reqinfo.getMethod()
            try:
                self.requests[domain]
            except KeyError:
                self.requests[domain] = {'POST': None, 'PUT': None, 'GET': None}
            self.requests[domain][method] = (reqinfo, reqbody)

    def actionPerformed(self, e):
        """
        Overrides ActionListener behaviour. Send current query to repeater.

        :param e: unused
        :return: None
        """
        req = self.requests[self._host]['POST'] or self.requests[self._host]['PUT'] or self.requests[self._host]['GET']
        if req:
            info = req[0]
            body = req[1]
            headers = body[:info.getBodyOffset()].tostring()

            try:
                self._overrideheaders[self._host]
            except KeyError:
                self._overrideheaders[self._host] = []

            repeater_body = StringUtil.toBytes(string_join(
                override_headers(headers, self._overrideheaders[self._host]),
                self._payload))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL #%s' % self._index)
            self._index += 1

    def ctx(self, host=None, payload=None, fname=None):
        """
        When a fname is specified and is a query file or a request is selected in the other tabs,
        enables the context menu to send to repeater tab

        :param host: should be not null
        :param payload: should be not null
        :param fname: should be not null
        :return: None
        """
        self._host = host
        self._payload = payload
        self._fname = fname

        if not self._fname.endswith('.query'):
            self.menuitem.setEnabled(False)
            self._burp_menuitem.setEnabled(False)
            return

        try:
            self.requests[host]
            self.menuitem.setEnabled(True)
            self._burp_menuitem.setEnabled(True)
        except KeyError:
            self.menuitem.setEnabled(False)
            self._burp_menuitem.setEnabled(False)

    def createMenuItems(self, invocation):
        """
        Overrides IContextMenuFactory callback

        :param invocation: handles menu selected invocation
        :return:
        """
        try:
            r = invocation.getSelectedMessages()[0]
            info = self._helpers.analyzeRequest(r)
            url = str(info.getUrl())
            if not any([x in url for x in URLS]):
                return None
            body = r.getRequest()[info.getBodyOffset():].tostring()
            for h in info.getHeaders():
                if h.lower().startswith("host:"):
                    domain = h[5:].strip()

            self.ctx(fname='dummy.query', host=domain, payload=body)
            mymenu = []
            mymenu.append(self._burp_menuitem)
        except Exception as ex:
            return None
        return mymenu