import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import urllib.request as urllib_request # for Python 3
    from urllib.parse import urlencode
except ImportError:
    import urllib2 as urllib_request # for Python 2 and Jython
    from urllib import urlencode

from java.awt.event import ActionListener
from javax.swing import JMenuItem

try:
    from burp import IProxyListener, IContextMenuFactory
except ImportError:
    IProxyListener = object
    IContextMenuFactory = object

from inql.utils import is_query


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


class SimpleMenuItem:
    """
    An OmniMenuItem implemented on top of a single item entry.
    """
    def __init__(self, text=None):
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)

    def add_action_listener(self, action_listener):
        self.menuitem.addActionListener(action_listener)

    def set_enabled(self, enabled):
        self.menuitem.setEnabled(enabled)


class SendToAction(ActionListener):
    """
    Class represeintg the action of sending something to BURP Repeater
    """
    def __init__(self, omnimenu, has_host, send_to):
        self._has_host = has_host
        self._send_to = send_to
        self._omnimenu = omnimenu
        self._omnimenu.add_action_listener(self)
        self.menuitem = self._omnimenu.menuitem
        self._host = None
        self._payload = None
        self._fname = None

    def actionPerformed(self, e):
        """
        Overrides ActionListener behaviour. Send current query to repeater.

        :param e: unused
        :return: None
        """
        self._send_to(self._host, self._payload)

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
            self._omnimenu.set_enabled(False)
            return

        if self._has_host(host):
            self._omnimenu.set_enabled(True)
        else:
            self._omnimenu.set_enabled(False)