import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import subprocess
import os

from java.awt.event import ActionListener
from java.awt import Desktop
from javax.swing import JMenuItem
from java.net import URI
from java.io import File as JavaFile

class URLOpener():
    """
    Open URLs on any major operative system (macOS, Linux XDG and Windows).
    """
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
        print("Cannot open url %s!!!" % url)


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
        URLOpener().open(JavaFile(self.target).toURI().toString())

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