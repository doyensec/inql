# coding: utf-8
from burp import IMessageEditorController

from javax.swing import JTabbedPane


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
