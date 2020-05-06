import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import json

from burp import IMessageEditorTab

from inql.utils import string_join


class ListGQLParameters(IMessageEditorTab):
    """
    GraphQL Editor TAB
    """
    def __init__(self,  callbacks, editable):
        self._helpers = callbacks.getHelpers()
        self._editable = editable
        self._txtInput = callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
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
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        """
        Check if we can enable or not the MessageEditorTab. Overrides IMessageEditorTab.

        :param content: message request/response
        :param isRequest: check if is request
        :return: True or False depending if the request is enabled to be edited with this tab.
        """
        if isRequest:
            rBody = self._helpers.analyzeRequest(content)

        else:
            rBody = self._helpers.analyzeResponse(content)

        message = content[rBody.getBodyOffset():].tostring().strip()
        try:
            content = json.loads(str(message))
            if isinstance(content, list):
                content = content[0]

            return 'query' in content and \
                   any([content['query'].strip().startswith(qtype) for qtype in ['query', 'mutation', 'subscription']])
        except ValueError:
            return False

    def setMessage(self, content, isRequest):
        """
        Message Setter. Overrides IMessageEditorTab.

        :param content: message request/response
        :param isRequest: check if is request
        :return: the modified body
        """
        if content is None:
            # Display Nothing for NoContent
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            r = self._helpers.analyzeRequest(content)

            message = content[r.getBodyOffset():].tostring()

            try:
                data = json.loads(str(message))
                if isinstance(data, list):
                    data = data[0]

                self._txtInput.setText(data['query'])
                self._txtInput.setEditable(self._editable)
                self._currentMessage = content
            except ValueError:
                pass

    def getMessage(self):
        """
        Message Getter. Overrides IMessageEditorTab.

        :return: the current message
        """
        if self._txtInput.isTextModified():
            try:
                query = self._txtInput.getText().tostring()

                r = self._helpers.analyzeRequest(self._currentMessage)
                message = self._currentMessage[r.getBodyOffset():].tostring()
                data = json.loads(str(message))
                if isinstance(data, list):
                    data[0]['query'] = query
                else:
                    data['query'] = query
                request_body = json.dumps(data, indent=4)
                return self._helpers.buildHttpMessage(r.getHeaders(), request_body)
            except Exception as ex:
                print(ex)
                return self._helpers.buildHttpMessage(r.getHeaders(), self._currentMessage[r.getBodyOffset():].tostring())


    def isModified(self):
        """
        Check if the message was modified.

        :return: True if the message was modified.
        """
        return self._txtInput.isTextModified()

    def getSeletedData(self):
        """
        Return the selected data.

        :return: the selected string.
        """
        return self._txtInput.getSelectedText()