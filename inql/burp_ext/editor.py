import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import json

from burp import IMessageEditorTab

from javax.swing import JFrame, JPanel, JLabel, JSplitPane
from java.awt import BorderLayout

from inql.widgets.payloadview import PayloadView


class GraphQLEditorTab(IMessageEditorTab):
    """
    GraphQL Editor TAB
    """
    def __init__(self,  callbacks, editable):
        self.payload_view = PayloadView(payload='', texteditor_factory=callbacks.createTextEditor, editable=editable)
        self._helpers = callbacks.getHelpers()
        self._currentMessage = ''

    def getTabCaption(self):
        """
        Define Message Editor Properties for GQL Editor

        :return: InQL burp message editor name
        """
        return "InQL"

    def getUiComponent(self):
        """
        Get UI Component. Overrides IMessageEditorTab.

        :return: UI txt component
        """
        return self.payload_view.this

    def isEnabled(self, content, isRequest):
        """
        Check if we can enable or not the MessageEditorTab. Overrides IMessageEditorTab.

        :param content: message request/response
        :param isRequest: check if is request
        :return: True or False depending if the request is enabled to be edited with this tab.
        """
        try:
            if isRequest:
                rBody = self._helpers.analyzeRequest(content)

            else:
                rBody = self._helpers.analyzeResponse(content)

            message = content[rBody.getBodyOffset():].tostring().strip()
            content = json.loads(str(message))
            if isinstance(content, list):
                content = content[0]

            return 'query' in content and \
                   any([content['query'].strip().startswith(qtype) for qtype in ['query', 'mutation', 'subscription', '{']])
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        """
        Message Setter. Overrides IMessageEditorTab.

        :param content: message request/response
        :param isRequest: check if is request
        :return: the modified body
        """
        if content is not None:
            r = self._helpers.analyzeRequest(content)
            self._currentMessage = content
            message = content[r.getBodyOffset():].tostring()

            try:
                self.payload_view.refresh(message)
            except ValueError:
                pass

    def getMessage(self):
        """
        Message Getter. Overrides IMessageEditorTab.

        :return: the current message
        """
        if self.isModified():
            try:
                request_body = self.payload_view.textarea().getText()
                r = self._helpers.analyzeRequest(self._currentMessage)
                return self._helpers.buildHttpMessage(r.getHeaders(), request_body)
            except Exception as ex:
                print(ex)
                return self._helpers.buildHttpMessage(r.getHeaders(), self._currentMessage[r.getBodyOffset():].tostring())


    def isModified(self):
        """
        Check if the message was modified.

        :return: True if the message was modified.
        """
        r = self._helpers.analyzeRequest(self._currentMessage)
        return self._currentMessage[r.getBodyOffset():].tostring() != self.payload_view.textarea().getText()


    def getSeletedData(self):
        """
        Return the selected data.

        :return: the selected string.
        """
        return  self.payload_view.textarea().getSeletedText()