import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import ActionListener
from java.awt import Desktop
from javax.swing import JMenuItem
from java.net import URI
import subprocess
import os


class BrowserAction(ActionListener):
    def __init__(self, text="Open In Browser"):
        self.text = text
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)
        self.menuitem.addActionListener(self)

        self.openers = [
            lambda url: Desktop.getDesktop().browse(URI(url)),
            lambda url: subprocess.call(["xdg-open", url]),
            lambda url: subprocess.call(["open", url])
        ]

    def actionPerformed(self, e):
        self.run(self.fname)

    def ctx(self, host=None, payload=None, fname=None):
        self.fname = os.path.abspath(fname)
        if self.fname.endswith('.html'):
            self.menuitem.setEnabled(True)
        else:
            self.menuitem.setEnabled(False)

    def run(self, url):
        for opener in self.openers:
            try:
                opener(url)
                return
            except:
                pass
