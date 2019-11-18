import platform

if platform.system() == "Java":
    from burp import IProxyListener
    from java.awt.event import ActionListener
    from javax.swing import JMenuItem
    from inql.constants import *
    from org.python.core.util import StringUtil
    from inql.utils import stringjoin

    class RepeaterSender(IProxyListener, ActionListener):
        def __init__(self, callbacks, helpers, text):
            self.requests = {}
            self.helpers = helpers
            self.callbacks = callbacks
            self.menuitem = JMenuItem(text)
            self.callbacks.registerProxyListener(self)
            self.menuitem.addActionListener(self)
            self.menuitem.setEnabled(False)
            self.index = 0
            self.host = None
            self.payload = None
            self.fname = None

        def processProxyMessage(self, messageIsRequest, message):
            if messageIsRequest:
                self.processRequest(self.helpers.analyzeRequest(message.getMessageInfo()), message.getMessageInfo().getRequest())

        def processRequest(self, reqinfo, reqbody):
            url = str(reqinfo.getUrl())
            if any([x in url for x in URLS]):
                for h in reqinfo.getHeaders():
                    if h.lower().startswith("host:"):
                        domain = h[5:].strip()

                method = reqinfo.getMethod()
                try:
                    self.requests[domain]
                except KeyError:
                    self.requests[domain] = {}
                self.requests[domain][method] = (reqinfo, reqbody)

        def actionPerformed(self, e):
            req = self.requests[self.host]['POST'] or self.requests[self.host]['PUT'] or self.requests[self.host]['GET']
            if req:
                info = req[0]
                body = req[1]
                headers = body[:info.getBodyOffset()].tostring()
                repeater_body = StringUtil.toBytes(stringjoin(headers, self.payload))
                self.callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(), info.getUrl().getProtocol() == 'https', repeater_body, 'GraphQL #%s' % self.index)
                self.index += 1

        def ctx(self, host=None, payload=None, fname=None):
            self.host = host
            self.payload = payload
            self.fname = fname

            try:
                self.requests[host]
                self.menuitem.setEnabled(True)
            except KeyError:
                self.menuitem.setEnabled(False)