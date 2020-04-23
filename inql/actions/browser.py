import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

try:
    import urllib.request as urllib_request # for Python 3
except ImportError:
    import urllib2 as urllib_request # for Python 2 and Jython

import subprocess
import os
import json

from java.awt.event import ActionListener
from java.awt import Desktop
from javax.swing import JMenuItem
from java.net import URI

class URLOpener():
    def __init__(self):
        self.openers = [
            lambda url: Desktop.getDesktop().browse(URI(url)),
            lambda url: subprocess.call(["xdg-open", url]),
            lambda url: subprocess.call(["open", url])
        ]

    def open(self, url):
        """
        Try to execute the first available browser. Since on every system (Darwin, Windows and Linux) this procedure is
        different, iterate on every procedure and exit on the first successful one or on the last one altogether.

        :param url: url to be opened
        :return: None
        """
        for opener in self.openers:
            try:
                opener(url)
                return
            except:
                pass

class BrowserAction(ActionListener):
    """
    BrowserAction performs a new "Open In Browser" action when the context is set to an HTML File.
    The idea is to show HTML documentation in a Browser, when generated and the context is correct
    """

    def __init__(self, text="Open In Browser"):
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)
        self.menuitem.addActionListener(self)

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """
        URLOpener().open(self.target)

    def ctx(self, host=None, payload=None, fname=None):
        """
        Setup the current context
        :param host: unused
        :param payload: unused
        :param fname: filename of the selected file
        :return: None
        """
        self.target = os.path.abspath(fname)
        if self.target.endswith('.html'):
            self.menuitem.setEnabled(True)
        else:
            self.menuitem.setEnabled(False)


class GraphIQLAction(ActionListener):
    """
    BrowserAction performs a new "Open In Browser" action when the context is set to an HTML File.
    The idea is to show HTML documentation in a Browser, when generated and the context is correct
    """

    def __init__(self, text="Open in GraphIQL Console"):
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)
        self.menuitem.addActionListener(self)
        self.lookup = {}

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """
        URLOpener().open(self.target)

    def ctx(self, host=None, payload=None, fname=None):
        """
        Setup the current context
        :param host: unused
        :param payload: unused
        :param fname: filename of the selected file
        :return: None
        """
        protocols = ['http', 'https']
        self.target = None
        for protocol in protocols:
            try:
                target = "%s://%s/graphiql" % (protocol, host)
                if not target in self.lookup:
                    urllib_request.urlopen(urllib_request.Request(target, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36'}))
                self.target = "%s://%s/graphiql" % (protocol, host)
                self.lookup[target] = True
                if os.path.abspath(fname).endswith('.query'):
                    self.target += "?query=%s" % urllib_request.quote(json.loads(payload)['query'])
            except Exception as ex:
                pass

        if self.target:
            self.menuitem.setEnabled(True)
        else:
            self.menuitem.setEnabled(False)
