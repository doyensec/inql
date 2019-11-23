#!/usr/bin/env jython
"""
Title: InQL Scanner
Author: Andrea Brancaleoni (@nJoyeneer)
Original Author: Paolo Stagno (@Void_Sec) - https://voidsec.com
Version: 1.0
Query a GraphQL endpoint with introspection in order to retrieve the documentation of all the Queries, Mutations & Subscriptions.
The script will also generate Queries, Mutations & Subscriptions templates (with optional placeholders) for all the known types.
It will also implements the following checks:
- search for known graphql paths
- search for exposed graphql development consoles
"""
import platform

if platform.system() == "Java":
    from array import array
    import json
    import tempfile
    import shutil
    import os
    # TODO: MUST merge this file to make it works as a standalone tool
    import query_process
    from widgets.tab import GraphQLPanel
    from actions.sendtorepeater import RepeaterSender

    from java.io import PrintWriter

    from constants import *

    from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, IScannerInsertionPointProvider, \
        IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue, ITab, IExtensionStateListener

    from utils import stringjoin

    class BurpExtender(IBurpExtender, IScannerInsertionPointProvider, IMessageEditorTabFactory, IScannerCheck, IExtensionStateListener):

        # Main Class for Burp Extenders
        def registerExtenderCallbacks(self, callbacks):
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            # TODO: use burp TMPDIR
            self.tmpdir = tempfile.mkdtemp()
            os.chdir(self.tmpdir)
            helpers = callbacks.getHelpers()
            callbacks.setExtensionName("InQL Scanner %s" % SCANNER_VERSION)
            callbacks.issueAlert("InQL Scanner Started")
            print("InQL Scanner Started! (tmpdir: %s )" % os.getcwd())
            stdout = PrintWriter(callbacks.getStdout(), True)
            stderr = PrintWriter(callbacks.getStderr(), True)
            # Registering GraphQL Tab
            callbacks.registerMessageEditorTabFactory(self)
            # Registering IScannerInsertionPointProvider class Object
            callbacks.registerScannerInsertionPointProvider(self)
            # Register ourselves as a custom scanner check
            callbacks.registerScannerCheck(self)
            # Register Suite Tab
            self.tab = GraphQLTab(callbacks, helpers)
            callbacks.addSuiteTab(self.tab)
            # Register extension state listener
            callbacks.registerExtensionStateListener(self)
            return

        def extensionUnloaded(self):
            os.chdir('/')
            shutil.rmtree(self.tmpdir, ignore_errors=False, onerror=None)
            self.tab.save()
            return

        # helper method to search a response for occurrences of a literal match string
        # and return a list of start/end offsets
        def _get_matches(self, response, match):
            matches = []
            start = 0
            reslen = len(response)
            matchlen = len(match)
            while start < reslen:
                """
                indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to)
                This method searches a piece of data for the first occurrence of a specified pattern.
                """
                start = self._helpers.indexOf(response, match, False, start, reslen)
                if start == -1:
                    break
                matches.append(array('i', [start, start + matchlen]))
                start += matchlen

            return matches

        # implement IScannerCheck
        def doPassiveScan(self, baseRequestResponse):
            issues = []
            for check in TECH_CHECKS:
                # look for matches of our passive check grep string
                matches = self._get_matches(baseRequestResponse.getResponse(), bytearray(check))
                if len(matches) != 0:
                    # report the issue
                    # httpService, url, httpMessages, name, detail, severity, confidence, issue background, remediation background, remediation details
                    issues.extend([CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                        "GraphQL Technology",
                        "The website is using GraphQL Technology!<br><br>"
                        "GraphQL is an open-source data query and manipulation language for APIs, and a runtime for fulfilling queries with existing data. GraphQL was developed internally by Facebook in 2012 before being publicly released in 2015.<br><br>"
                        "It provides an efficient, powerful and flexible approach to developing web APIs, and has been compared and contrasted with REST and other web service architectures. It allows clients to define the structure of the data required, and exactly the same structure of the data is returned from the server, therefore preventing excessively large amounts of data from being returned, but this has implications for how effective web caching of query results can be. The flexibility and richness of the query language also adds complexity that may not be worthwhile for simple APIs. It consists of a type system, query language and execution semantics, static validation, and type introspection.<br><br>"
                        "GraphQL supports reading, writing (mutating) and subscribing to changes to data (realtime updates).",
                        "Information", "Firm", "Not posing any imminent security risk.",
                        "<ul><li><a href='https://graphql.org/'>GraphQL</a></li></ul>",
                        ""
                    )])

            for check in CONSOLE_CHECKS:
                # look for matches of our passive check grep string
                matches = self._get_matches(baseRequestResponse.getResponse(), bytearray(check))
                if len(matches) != 0:
                    # report the issue
                    # httpService, url, httpMessages, name, detail, severity, confidence, issue background, remediation background, remediation details
                    issues.extend([CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                        "Exposed GraphQL Development Console",
                        "GraphQL is a query language for APIs and a runtime for fulfilling queries with existing data.<br><br>"
                        "<b>GraphiQL/GraphQL Playground</b> are in-browser tools for writing, validating, and testing GraphQL queries.<br><br>"
                        "The response contains the following string: <b>%s</b>." % check,
                        "Low", "Firm", "Not posing any imminent security risk.",
                        "<ul>"
                        "<li><a href='https://graphql.org/'>GraphQL</a></li>"
                        "<li><a href='https://github.com/graphql/graphiql'>GraphiQL</a></li>"
                        "<li><a href='https://github.com/prisma/graphql-playground'>GraphQL Playground</a></li>"
                        "</ul>",
                        "Remove the GraphQL development console from web-application in a production stage.<br><br>"
                        "Disable GraphiQL<br>"
                        "<pre>if (process.env.NODE_ENV === 'development') {</pre></br>"
                        "<pre>  app.all(</pre></br>"
                        "<pre>    '/graphiql',</pre></br>"
                        "<pre>    graphiqlExpress({</pre></br>"
                        "<pre>      endpointURL: '/graphql',</pre></br>"
                        "<pre>    }),</pre></br>"
                        "<pre>  );</pre></br>"
                        "<pre>}</pre>"
                    )])

            return issues

        # active scan
        def doActiveScan(self, baseRequestResponse, insertionPoint):
            issues = []
            # will request the URLS, passive scanner will do the grep and match
            for url in URLS:
                path = self._callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl().getPath()
                # this thing replace the path inside the old bytearray for the new request
                newReq = self._callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()).replace(path, url,
                                                                                                              1)
                result = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
                for check in TECH_CHECKS:
                    # look for matches of our passive check grep string
                    matches = self._get_matches(result.getResponse(), bytearray(check))
                    if len(matches) != 0:
                        # report the issue
                        # httpService, url, httpMessages, name, detail, severity, confidence, issue background, remediation background, remediation details
                        issues.extend([CustomScanIssue(
                            result.getHttpService(),
                            self._helpers.analyzeRequest(result).getUrl(),
                            [self._callbacks.applyMarkers(result, None, matches)],
                            "GraphQL Technology",
                            "The website is using GraphQL Technology!<br><br>"
                            "GraphQL is an open-source data query and manipulation language for APIs, and a runtime for fulfilling queries with existing data. GraphQL was developed internally by Facebook in 2012 before being publicly released in 2015.<br><br>"
                            "It provides an efficient, powerful and flexible approach to developing web APIs, and has been compared and contrasted with REST and other web service architectures. It allows clients to define the structure of the data required, and exactly the same structure of the data is returned from the server, therefore preventing excessively large amounts of data from being returned, but this has implications for how effective web caching of query results can be. The flexibility and richness of the query language also adds complexity that may not be worthwhile for simple APIs. It consists of a type system, query language and execution semantics, static validation, and type introspection.<br><br>"
                            "GraphQL supports reading, writing (mutating) and subscribing to changes to data (realtime updates).",
                            "Information", "Firm", "Not posing any imminent security risk.",
                            "<ul><li><a href='https://graphql.org/'>GraphQL</a></li></ul>",
                            ""
                        )])

                for check in CONSOLE_CHECKS:
                    # look for matches of our passive check grep string
                    matches = self._get_matches(result.getResponse(), bytearray(check))
                    if len(matches) != 0:
                        # report the issue
                        # httpService, url, httpMessages, name, detail, severity, confidence, issue background, remediation background, remediation details
                        issues.extend([CustomScanIssue(
                            result.getHttpService(),
                            self._helpers.analyzeRequest(result).getUrl(),
                            [self._callbacks.applyMarkers(result, None, matches)],
                            "Exposed GraphQL Development Console",
                            "GraphQL is a query language for APIs and a runtime for fulfilling queries with existing data.<br><br>"
                            "<b>GraphiQL/GraphQL Playground</b> are in-browser tools for writing, validating, and testing GraphQL queries.<br><br>"
                            "The response contains the following string: <b>%s</b>." % check,
                            "Low", "Firm", "Not posing any imminent security risk.",
                            "<ul>"
                            "<li><a href='https://graphql.org/'>GraphQL</a></li>"
                            "<li><a href='https://github.com/graphql/graphiql'>GraphiQL</a></li>"
                            "<li><a href='https://github.com/prisma/graphql-playground'>GraphQL Playground</a></li>"
                            "</ul>",
                            "Remove the GraphQL development console from web-application in a production stage.<br><br>"
                            "Disable GraphiQL<br>"
                            "<pre>if (process.env.NODE_ENV === 'development') {</pre></br>"
                            "<pre>  app.all(</pre></br>"
                            "<pre>    '/graphiql',</pre></br>"
                            "<pre>    graphiqlExpress({</pre></br>"
                            "<pre>      endpointURL: '/graphql',</pre></br>"
                            "<pre>    }),</pre></br>"
                            "<pre>  );</pre></br>"
                            "<pre>}</pre>"
                        )])

            return issues

        def consolidateDuplicateIssues(self, existingIssue, newIssue):
            # This method is called when multiple issues are reported for the same URL
            # path by the same extension-provided check. The value we return from this
            # method determines how/whether Burp consolidates the multiple issues
            # to prevent duplication
            #
            # Do not report same issues on the same path

            if (existingIssue.getHttpMessages()[0].getHttpService().getHost() == newIssue.getHttpMessages()[
                0].getHttpService().getHost()) and (
                    existingIssue.getHttpMessages()[0].getHttpService().getPort() == newIssue.getHttpMessages()[
                0].getHttpService().getPort()):
                return -1
            else:
                return 0

        # Define function to fetch Insertion Points
        def getInsertionPoints(self, baseRequestResponse):
            # Get the parameter for insertion
            dataParameter = self._helpers.getRequestParameter(baseRequestResponse.getRequest(), "data")
            if dataParameter is None:
                return None
            else:
                # One insertion point at a time
                return [InsertionPoint(self._helpers, baseRequestResponse.getRequest(), dataParameter.getValue())]

        def createNewInstance(self, controller, editable):
            return listGQLParameters(self, controller, editable)


    # Class implementing IScanIssue to hold our custom scan issue details
    class CustomScanIssue(IScanIssue):
        def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, issuebg, rembg, remdet):
            self._httpService = httpService
            self._url = url
            self._httpMessages = httpMessages
            self._name = name
            self._detail = detail
            self._severity = severity
            self._confidence = confidence
            self._issuebg = issuebg
            self._rembg = rembg
            self._remdet = remdet

        def getUrl(self):
            return self._url

        def getIssueName(self):
            return self._name

        # See http://portswigger.net/burp/help/scanner_issuetypes.html
        def getIssueType(self):
            return 0

        # "High", "Medium", "Low", "Information" or "False positive"
        def getSeverity(self):
            return self._severity

        # "Certain", "Firm" or "Tentative"
        def getConfidence(self):
            return self._confidence

        def getIssueBackground(self):
            return self._issuebg

        def getRemediationBackground(self):
            return self._rembg

        def getIssueDetail(self):
            return self._detail

        def getRemediationDetail(self):
            return self._remdet

        def getHttpMessages(self):
            return self._httpMessages

        def getHttpService(self):
            return self._httpService


    class listGQLParameters(IMessageEditorTab):
        def __init__(self, extender, controller, editable):
            self._extender = extender
            self._helpers = extender._helpers
            self._editable = editable
            self._txtInput = extender._callbacks.createTextEditor()
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

            return

        # Define Message Editor Properties for GQL Editor
        def getTabCaption(self):
            return "InQL"

        def getUiComponent(self):
            return self._txtInput.getComponent()

        def isEnabled(self, content, isRequest):
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
                    gql_msg = stringjoin(garbage, clean)

                self._txtInput.setText(gql_msg)
                self._txtInput.setEditable(self._editable)

            self._currentMessage = content
            return

        def getMessage(self):
            if self._txtInput.isTextModified():
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
            return self._txtInput.isTextModified()

        def getSeletedData(self):
            return self._txtInput.getSelectedText()


    class InsertionPoint(IScannerInsertionPoint):

        def __init__(self, helpers, baseRequest, dataParameter):
            self._helpers = helpers
            self._baseRequest = baseRequest
            self.final_positions = []
            dataParameter = helpers.bytesToString(dataParameter)
            # Implement Query Process to get Insertion Points
            request = query_process(dataParameter) # TODO: isn't this thing completely bogus?
            request.findInsertionPoints()
            self.final_positions = request.findFinalPositions()

            # Loop through to Create prefix and suffix for insertion Points
            for ins_point in self.final_positions:
                start = ins_point[0]
                end = ins_point[1]
                self._insertionPointPrefix = dataParameter[:start]
                if (end == -1):
                    end = dataParameter.length()
                self._baseValue = dataParameter[start:end]
                self._insertionPointSuffix = dataParameter[end:]

            return

        def getInsertionPointName(self):
            return self._baseValue

        def buildRequest(self, payload):
            input(stringjoin(self._insertionPointPrefix, self._helpers.bytesToString(payload), self._insertionPointSuffix))
            return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter("data"), input,
                                                 IParameter.PARAM_BODY)

        def getPayloadOffsets(self, payload):
            return None

        def getInsertionPointType(self):
            return INS_EXTENSION_PROVIDED


    # JAVA GUI
    class GraphQLTab(ITab):

        def __init__(self, callbacks, helpers):
            self.callbacks = callbacks
            self.helpers = helpers

        def getTabCaption(self):
            return "InQL Scanner"

        def getUiComponent(self):
            repeater_sender = RepeaterSender(self.callbacks, self.helpers, "Send to Repeater")
            try:
                restore = self.callbacks.loadExtensionSetting(GraphQLPanel.__name__)
            except Exception as ex:
                print("Cannot restore state! %s" % ex)
                restore = None
            self.panel = GraphQLPanel(
                actions=[repeater_sender],
                restore=restore)
            self.callbacks.customizeUiComponent(self.panel.this)
            return self.panel.this

        def save(self):
            try:
                self.callbacks.saveExtensionSetting(self.panel.__class__.__name__, self.panel.state())
            except:
                print("Cannot save state!")
