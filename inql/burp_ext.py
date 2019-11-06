#!/usr/bin/env jython
"""
Title: GraphQL Scanner
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
    # JAVA GUI Import
    from java.awt import Component
    from java.awt import Color
    import java.awt
    from javax.swing import (BoxLayout, ImageIcon, JButton, JFrame, JPanel,
                             JPasswordField, JLabel, JTextArea, JTextField, JScrollPane,
                             SwingConstants, WindowConstants, GroupLayout, JCheckBox, JTree)
    import javax
    from java.lang import Short, Integer
    from java.io import PrintWriter
    # Burp Suite Import
    from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, IScannerInsertionPointProvider, \
        IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue, ITab
    from array import array
    import json
    import os
    # TODO: MUST merge this file to make it works as a standalone tool
    import query_process
    from introspection import init
    from filetree import FileTree

    SCANNER_VERSION = "1.0"
    DEBUG = False

    tech_checks = {
        '{"data":{"__schema":{',
        "graphql-ws"
    }

    console_checks = {
        "GraphiQL",
        "GraphQL Playground",
        "GraphQL Console",
        "graphql-playground"
    }

    urls = {
        "/graphql.php",
        "/graphql",
        "/graphiql",
        "/graphql/console/",
        "/swapi-graphql/",
        "/gql",
        "/graphql/subscriptions",
        "/graphql/subscription"
    }


    class AttrDict(dict):
        def __init__(self, *args, **kwargs):
            super(AttrDict, self).__init__(*args, **kwargs)
            self.__dict__ = self


    class BurpExtender(IBurpExtender, IScannerInsertionPointProvider, IMessageEditorTabFactory, IScannerCheck):
        # Main Class for Burp Extenders
        def registerExtenderCallbacks(self, callbacks):
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            helpers = callbacks.getHelpers()
            callbacks.setExtensionName("GraphQL Scanner v." + SCANNER_VERSION)
            callbacks.issueAlert("GraphQL Scanner Started")
            print "GraphQL Scanner Started!"
            stdout = PrintWriter(callbacks.getStdout(), True)
            stderr = PrintWriter(callbacks.getStderr(), True)
            # Registering GraphQL Tab
            callbacks.registerMessageEditorTabFactory(self)
            # Registering IScannerInsertionPointProvider class Object
            callbacks.registerScannerInsertionPointProvider(self)
            # Register ourselves as a custom scanner check
            callbacks.registerScannerCheck(self)
            # Register Suite Tab
            callbacks.addSuiteTab(GraphQLTab(callbacks, helpers))
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
            for check in tech_checks:
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

            for check in console_checks:
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
                        "The response contains the following string: <b>" + check + "</b>.",
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
            # will request the urls, passive scanner will do the grep and match
            for url in urls:
                path = self._callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl().getPath()
                # this thing replace the path inside the old bytearray for the new request
                newReq = self._callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()).replace(path, url,
                                                                                                              1)
                result = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
                for check in tech_checks:
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

                for check in console_checks:
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
                            "The response contains the following string: <b>" + check + "</b>.",
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
            return "GraphQL"

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
                # print "Starting GQL parsing and gql Indicator found: %s"%message[:17]
                return True
            else:

                var_pos = message.find(self._variable)
                if len(message) > 2 and var_pos > 0:
                    # print "GQL Indicator found: %s" % message[var_pos:var_pos+17]
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
                    print "Sorry, this doesnt look like a Graph Query!"
                    print ValueError
                    return

                garbage = message[:limit]
                clean = message[limit:]

                try:
                    gql_msg = garbage.strip() + '\n' + json.dumps(json.loads(clean), indent=4)
                    # gql_msg = re.sub(r'\\n', '\n', gql_msg)
                except Exception:
                    print("Problem parsing the setMessage")
                    print(Exception)
                    gql_msg = garbage + clean

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
                    print "Problem Getting the Message After Modification"
                    print Exception

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
            input(self._insertionPointPrefix + self._helpers.bytesToString(payload) + self._insertionPointSuffix)
            return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter("data"), input,
                                                 IParameter.PARAM_BODY)

        def getPayloadOffsets(self, payload):
            return None

        def getInsertionPointType(self):
            return INS_EXTENSION_PROVIDED


    def debug_msg(message):
        if DEBUG:
            print message


    # JAVA GUI
    class GraphQLTab(ITab):

        def __init__(self, callbacks, helpers):
            self.callbacks = callbacks
            self.helpers = helpers

        def getTabCaption(self):
            return "GraphQL Scanner"

        def getUiComponent(self):
            panel = GraphQLPanel(self.callbacks, self.helpers)
            self.callbacks.customizeUiComponent(panel.this)
            return panel.this


    class GraphQLPanel:
        # XXX: inheriting from Java classes is very tricky. It is preferable to use
        #      the decorator pattern instead.
        def __init__(self, callbacks, helpers):
            self.callbacks = callbacks
            self.helpers = helpers
            self.this = JPanel()
            self.initComponents()

        def initComponents(self):
            jLabel1 = javax.swing.JLabel()
            url = javax.swing.JTextField()
            self.url = url
            LoadJSON = javax.swing.JButton()
            self.LoadJSON = LoadJSON
            jScrollPane2 = javax.swing.JScrollPane()
            TextArea = javax.swing.JTextArea()
            self.TextArea = TextArea
            jLabel2 = javax.swing.JLabel()
            jLabel3 = javax.swing.JLabel()
            LoadPlaceholders = javax.swing.JCheckBox()
            self.LoadPlaceholders = LoadPlaceholders
            Loadurl = javax.swing.JButton()
            self.Loadurl = Loadurl
            jScrollPane3 = javax.swing.JScrollPane()
            self.FT = FileTree(os.getcwd(),TextArea)
            Tree = self.FT.this

            jLabel1.setLabelFor(url)
            jLabel1.setText("URL or File Location:")

            url.setText("http://example.com/graphql or /tmp/schema.json")
            url.setName("url")
            url.setSelectionColor(java.awt.Color(255, 153, 51))

            LoadJSON.setText("Load JSON")
            LoadJSON.setToolTipText("Load a JSON schema from a local file")
            LoadJSON.setName("LoadJSON")
            LoadJSON.addActionListener(
                lambda evt: LoadJSONActionPerformed(self, evt, url, LoadPlaceholders))

            TextArea.setColumns(20)
            TextArea.setRows(5)
            TextArea.setName("TextArea")
            TextArea.setSelectionColor(java.awt.Color(255, 153, 51))
            jScrollPane2.setViewportView(TextArea)

            jLabel2.setText("Queries, mutations and subscriptions")

            jLabel3.setLabelFor(TextArea)
            jLabel3.setText("Selected template:")

            LoadPlaceholders.setSelected(True)
            LoadPlaceholders.setText("Load template placeholders")
            LoadPlaceholders.setToolTipText("Load placeholders for the templates")
            LoadPlaceholders.setName("LoadPlaceholders")

            Loadurl.setText("Load URL")
            Loadurl.setToolTipText("Query a remote GraphQL backend (introspection)")
            Loadurl.addActionListener(
                lambda evt: LoadurlActionPerformed(self, evt, url, LoadPlaceholders))

            # Tree.setToolTipText("Select an item to load it's template")
            jScrollPane3.setViewportView(Tree)
            # JAVA GUI LAYOUT
            # --------------------
            layout = javax.swing.GroupLayout(self.this)
            self.this.setLayout(layout)
            layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                              .addContainerGap()
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                    .addGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jLabel2)
                        .addGroup(layout.createSequentialGroup()
                                  .addGap(6, 6, 6)
                                  .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 231,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGap(12, 12, 12)
                    .addGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jScrollPane2)
                        .addGroup(layout.createSequentialGroup()
                                  .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                  .addComponent(LoadPlaceholders))))
                                        .addGroup(layout.createSequentialGroup()
                                                  .addComponent(jLabel1)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(url, javax.swing.GroupLayout.PREFERRED_SIZE, 421,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(LoadJSON)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(Loadurl)))
                              .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
            layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                              .addContainerGap()
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel1)
                                        .addComponent(url, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                      javax.swing.GroupLayout.DEFAULT_SIZE,
                                                      javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(LoadJSON)
                                        .addComponent(Loadurl))
                              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                               javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel2)
                                        .addComponent(jLabel3)
                                        .addComponent(LoadPlaceholders))
                              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, False)
                                        .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 403,
                                                      Short.MAX_VALUE)
                                        .addComponent(jScrollPane3))
                              .addContainerGap())
            )
            # --------------------


    def LoadJSONActionPerformed(self, evt, url, LoadPlaceholders):
        target = url.getText()
        if checktarget(target):
            print "Loading JSON schema from: " + target
            run(self, target, LoadPlaceholders, "JSON")
        pass


    def LoadurlActionPerformed(self, evt, url, LoadPlaceholders):
        target = url.getText()
        if checktarget(target):
            print "Quering GraphQL schema from: " + target
            run(self, target, LoadPlaceholders, "URL")
        pass


    def checktarget(target):
        if target != "http://example.com/graphql or /tmp/schema.json" and target is not None and target != "":
            return True

        return False


    def run(self, target, LoadPlaceholders, flag):
        if flag == "JSON":
            if LoadPlaceholders.isSelected():
                args = {"schema_json_file": target, "detect": True, "key": None, "proxy": None, "target": None}
            else:
                args = {"schema_json_file": target, "detect": "", "key": None, "proxy": None, "target": None}
        else:
            if LoadPlaceholders.isSelected():
                args = {"target": target, "detect": True, "key": None, "proxy": None, "schema_json_file": None}
            else:
                args = {"target": target, "detect": "", "key": None, "proxy": None, "schema_json_file": None}

        # call init method from Introspection tool
        init(AttrDict(args))
        self.FT.refresh()
        return
else:
    print "Load this file inside Burp Suite, if you need the stand-alone tool run: Introspection.py"
