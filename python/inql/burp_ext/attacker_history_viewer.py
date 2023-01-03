from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from javax.swing import JTabbedPane
from burp import IMessageEditorController

class AttackerHistoryViewer(IMessageEditorController):
    def __init__(self, createMessageEditor):
        self.createMessageEditor = createMessageEditor

        self.request_editor = self.createMessageEditor(self, False)
        self.response_editor = self.createMessageEditor(self, False)

    def render(self):
        tabs = JTabbedPane()
        tabs.addTab("Request", self.request_editor.getComponent())
        tabs.addTab("Response", self.response_editor.getComponent())
        return tabs

    def getHttpService(self):
        return self.current.getHttpService()

    def getRequest(self):
        return self.current.getRequest()

    def getResponse(self):
        return self.current.getResponse()
