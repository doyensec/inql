import json

try:
    import urllib.request as urllib_request # for Python 3
    from urllib.parse import urlencode
except ImportError:
    import urllib2 as urllib_request # for Python 2 and Jython
    from urllib import urlencode

from java.awt.event import ActionListener
from javax.swing import JMenuItem

from org.python.core.util import StringUtil

from burp import IProxyListener, IContextMenuFactory

from inql.actions.sendto import HTTPMutator
from inql.utils import is_query, override_headers, string_join, override_uri, clean_dict, multipart, random_string, querify


class OmniMenuItem(IContextMenuFactory):
    """Menu item for burp and inql interface. IT contains same action but it is shown in multiple places"""
    def __init__(self, helpers=None, callbacks=None, text=''):
        self._helpers = helpers
        self._callbacks = callbacks
        self.menuitem = JMenuItem(text)
        self._burp_menuitem = JMenuItem("inql: %s" % text)
        self.set_enabled(False)
        self._callbacks.registerContextMenuFactory(self)

    def add_action_listener(self, action_listener):
        """
        add a new action listener to the given UI items.
        """
        self._action_listener = action_listener
        self.menuitem.addActionListener(action_listener)
        self._burp_menuitem.addActionListener(action_listener)

    def set_enabled(self, enabled):
        """
        Enables or disables the menuitme
        """
        self.menuitem.setEnabled(enabled)
        self._burp_menuitem.setEnabled(enabled)

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
            body = r.getRequest()[info.getBodyOffset():].tostring()
            if not is_query(body):
                return None
            for h in info.getHeaders():
                if h.lower().startswith("host:"):
                    domain = h[5:].strip()

            self._action_listener.ctx(fname='dummy.query', host=domain, payload=body)
            mymenu = []
            mymenu.append(self._burp_menuitem)
        except Exception as ex:
            return None
        return mymenu


class BurpHTTPMutator(HTTPMutator, IProxyListener):
    def __init__(self, callbacks=None, helpers=None, overrideheaders=None, requests=None, stub_responses=None):
        super(BurpHTTPMutator, self).__init__(overrideheaders=overrideheaders, requests=requests, stub_responses=stub_responses)

        if helpers and callbacks:
            self._helpers = helpers
            self._callbacks = callbacks
            self._callbacks.registerProxyListener(self)
            for r in self._callbacks.getProxyHistory():
                self._process_request(self._helpers.analyzeRequest(r), r.getRequest())

    def _process_request(self, reqinfo, reqbody):
        """
        Process request and extract key values

        :param reqinfo:
        :param reqbody:
        :return:
        """
        url = str(reqinfo.getUrl())
        if is_query(reqbody[reqinfo.getBodyOffset():].tostring()):
            for h in reqinfo.getHeaders():
                if h.lower().startswith("host:"):
                    domain = h[5:].strip()

            method = reqinfo.getMethod()
            try:
                self._requests[domain]
            except KeyError:
                self._requests[domain] = {'POST': None, 'PUT': None, 'GET': None, 'url': None}
            self._requests[domain][method] = (reqinfo, reqbody)
            self._requests[domain]['url'] = url

    def processProxyMessage(self, messageIsRequest, message):
        """
        Implements IProxyListener method

        :param messageIsRequest: True if BURP Message is a request
        :param message: message content
        :return: None
        """
        if self._helpers and self._callbacks and messageIsRequest:
            self._process_request(self._helpers.analyzeRequest(message.getMessageInfo()),
                                  message.getMessageInfo().getRequest())

    def send_to_repeater(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            headers = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            headers = override_headers(headers, self._overrideheaders[host])
            repeater_body = StringUtil.toBytes(string_join(
                headers,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring(),
                payload))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL #%s' % self._index)
            self._index += 1

    def send_to_repeater_get_query(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            metadata = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            metadata = override_headers(metadata, self._overrideheaders[host])
            content = json.loads(payload)
            if isinstance(content, list):
                content = content[0]
            metadata = override_uri(metadata, method="GET", query=urlencode(clean_dict(content)))

            repeater_body = StringUtil.toBytes(string_join(
                metadata,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring()))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL - GET query #%s' % self._index)
            self._index += 1

    def send_to_repeater_post_urlencoded_body(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            headers = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            headers = override_headers(headers, self._overrideheaders[host])
            headers = override_headers(headers, [("Content-Type", "application/x-www-form-urlencoded")])
            headers = override_uri(headers, method="POST")
            content = json.loads(payload)
            if isinstance(content, list):
                content = content[0]
            repeater_body = StringUtil.toBytes(string_join(
                headers,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring(),
                urlencode(querify(clean_dict(content)))))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL - POST urlencoded #%s' % self._index)
            self._index += 1

    def send_to_repeater_post_form_data_body(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            headers = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            headers = override_headers(headers, self._overrideheaders[host])
            boundary = "---------------------------%s" % random_string()
            headers = override_headers(headers, [("Content-Type", "multipart/form-data, boundary=%s" % boundary)])
            headers = override_uri(headers, method="POST")
            content = json.loads(payload)
            if isinstance(content, list):
                content = content[0]
            repeater_body = StringUtil.toBytes(string_join(
                headers,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring(),
                multipart(data=querify(clean_dict(content)), boundary=boundary)))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL - POST form-data #%s' % self._index)
            self._index += 1