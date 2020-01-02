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
        # Define Query Indicators To Identify a GQL
        self._GQLIndicator = [
            '[{"operationName"',
            '{"operationName":',
            '[{"query":"query ',
            '{"query":"mutation',
            '{"query":"subscription',
            '{"query":"',
            '{"data":',
            '[{"data":']
        self._variable = 'variables": {'

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
        isgql = False
        if isRequest:
            rBody = self._helpers.analyzeRequest(content)

        else:
            rBody = self._helpers.analyzeResponse(content)

        message = content[rBody.getBodyOffset():].tostring()
        for indicator in self._GQLIndicator:
            if message.startswith(indicator):
                isgql = True

        if len(message) > 2 and isgql:
            return True
        else:

            var_pos = message.find(self._variable)
            if len(message) > 2 and var_pos > 0:
                return True

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
            if isRequest:
                rBody = self._helpers.analyzeRequest(content)
            else:
                rBody = self._helpers.analyzeResponse(content)

            message = content[rBody.getBodyOffset():].tostring()

            try:
                limit = min(
                    message.index('{') if '{' in message else len(message),
                    message.index('[') if '[' in message else len(message)
                )
            except ValueError:
                print("Sorry, this doesnt look like a Graph Query!")
                return

            garbage = message[:limit]
            clean = message[limit:]

            try:
                gql_msg = "\n".join(garbage.strip(), json.dumps(json.loads(clean), indent=4))
            except Exception:
                print("A problem occurred parsing the setMessage")
                print(Exception)
                gql_msg = string_join(garbage, clean)

            self._txtInput.setText(gql_msg)
            self._txtInput.setEditable(self._editable)

        self._currentMessage = content

    def getMessage(self):
        """
        Message Getter. Overrides IMessageEditorTab.

        :return: the current message
        """
        if self._txtInput.isTextModified():
            data = ""
            try:
                # self._manual = True
                data = self._txtInput.getText()

            except Exception:
                print("A problem occurred getting the message after modification")

            # Update Request After Modification
            r = self._helpers.analyzeRequest(self._currentMessage)

            # return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
            return self._helpers.buildHttpMessage(r.getHeaders(), data)

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