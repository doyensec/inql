import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from array import array

from burp import IScanIssue, IScannerCheck

from inql.constants import TECH_CHECKS, CONSOLE_CHECKS, URLS


class _CustomScanIssue(IScanIssue):
    """
    Custom Scan Issue Container
    """
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence, issuebg, rembg, remdet):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._issuebg = issuebg
        self._rembg = rembg
        self._remdet = remdet

    def getUrl(self):
        """
        Overrides IScanIssue

        :return: the URL
        """
        return self._url

    def getIssueName(self):
        """
        Overrides IScanIssue

        :return: the Issue Name
        """
        return self._name

    def getIssueType(self):
        """
        Overrides IScanIssue

        See http://portswigger.net/burp/help/scanner_issuetypes.html

        :return: always 0
        """
        return 0

    def getSeverity(self):
        """
        Overrides IScanIssue

        :return: "High", "Medium", "Low", "Information" or "False positive"
        """
        return self._severity

    def getConfidence(self):
        """
        Overrides IScanIssue

        :return: "Certain", "Firm" or "Tentative"
        """
        return self._confidence

    def getIssueBackground(self):
        """
        Overrides IScanIssue

        :return: issue background
        """
        return self._issuebg

    def getRemediationBackground(self):
        """
        Overrides IScanIssue

        :return: remediation background
        """
        return self._rembg

    def getIssueDetail(self):
        """
        Overrides IScanIssue

        :return: issue detail
        """
        return self._detail

    def getRemediationDetail(self):
        """
        Overrides IScanIssue

        :return: remediation detail
        """
        return self._remdet

    def getHttpMessages(self):
        """
        Overrides IScanIssue

        :return: Http messages content
        """
        return self._http_messages

    def getHttpService(self):
        """
        Overrides IScanIssue

        :return: Http Service
        """
        return self._http_service


class BurpScannerCheck(IScannerCheck):
    """
    Scanner Check
    """
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

    def _get_matches(self, response, match):
        """
        helper method to search a response for occurrences of a literal match string
        and return a list of start/end offsets.

        :param response: response object to search for
        :param match: search term
        :return: matches
        """
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

    def doPassiveScan(self, baseRequestResponse):
        """
        Override IScannerCheck method.

        :param baseRequestResponse: burp requestResponse message.
        :return: issues containing all the burp findings, they will be added to the found issues.
        """
        issues = []

        if not (200 <= baseRequestResponse.getStatusCode() < 300):
            return issues
            
        for check in TECH_CHECKS:
            # look for matches of our passive check grep string
            matches = self._get_matches(baseRequestResponse.getResponse(), bytearray(check))
            if len(matches) != 0:
                # report the issue
                issues.extend([_CustomScanIssue(
                    http_service=baseRequestResponse.getHttpService(),
                    url=self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    http_messages=[self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    name="GraphQL Technology",
                    detail="The website is using GraphQL Technology!<br><br>"
                    "GraphQL is an open-source data query and manipulation language for APIs, and a runtime for fulfilling queries with existing data. GraphQL was developed internally by Facebook in 2012 before being publicly released in 2015.<br><br>"
                    "It provides an efficient, powerful and flexible approach to developing web APIs, and has been compared and contrasted with REST and other web service architectures. It allows clients to define the structure of the data required, and exactly the same structure of the data is returned from the server, therefore preventing excessively large amounts of data from being returned, but this has implications for how effective web caching of query results can be. The flexibility and richness of the query language also adds complexity that may not be worthwhile for simple APIs. It consists of a type system, query language and execution semantics, static validation, and type introspection.<br><br>"
                    "GraphQL supports reading, writing (mutating) and subscribing to changes to data (realtime updates).",
                    severity="Information", confidence="Firm", issuebg="Not posing any imminent security risk.",
                    rembg="<ul><li><a href='https://graphql.org/'>GraphQL</a></li></ul>",
                    remdet=""
                )])

        for check in CONSOLE_CHECKS:
            # look for matches of our passive check grep string
            matches = self._get_matches(baseRequestResponse.getResponse(), bytearray(check))
            if len(matches) != 0:
                # report the issue
                issues.extend([_CustomScanIssue(
                    http_service=baseRequestResponse.getHttpService(),
                    url=self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    http_messages=[self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    name="Exposed GraphQL Development Console",
                    detail="GraphQL is a query language for APIs and a runtime for fulfilling queries with existing data.<br><br>"
                    "<b>GraphiQL/GraphQL Playground</b> are in-browser tools for writing, validating, and testing GraphQL queries.<br><br>"
                    "The response contains the following string: <b>%s</b>." % check,
                    severity="Low", confidence="Firm", issuebg="Not posing any imminent security risk.",
                    rembg="<ul>"
                    "<li><a href='https://graphql.org/'>GraphQL</a></li>"
                    "<li><a href='https://github.com/graphql/graphiql'>GraphiQL</a></li>"
                    "<li><a href='https://github.com/prisma/graphql-playground'>GraphQL Playground</a></li>"
                    "</ul>",
                    remdet="Remove the GraphQL development console from web-application in a production stage.<br><br>"
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

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """
        Override IScannerCheck method.

        :param baseRequestResponse: burp requestResponse message.
        :param insertionPoint: where to insert the payload, never used
        :return: issues containing all the burp findings, they will be added to the found issues.
        """

        issues = []

        if not (200 <= baseRequestResponse.getStatusCode() < 300):
            return issues
            
        # will request the URLS, passive scanner will do the grep and match
        for url in URLS:
            path = self._callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl().getPath()
            # replace the path inside the old bytearray for the new request
            newReq = self._callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()).replace(path, url,
                                                                                                          1)
            result = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
            for check in TECH_CHECKS:
                # look for matches of our passive check grep string
                matches = self._get_matches(result.getResponse(), bytearray(check))
                if len(matches) != 0:
                    # report the issue
                    issues.extend([_CustomScanIssue(
                        http_service=result.getHttpService(),
                        url=self._helpers.analyzeRequest(result).getUrl(),
                        http_messages=[self._callbacks.applyMarkers(result, None, matches)],
                        name="GraphQL Technology",
                        detail="The website is using GraphQL Technology!<br><br>"
                        "GraphQL is an open-source data query and manipulation language for APIs, and a runtime for fulfilling queries with existing data. GraphQL was developed internally by Facebook in 2012 before being publicly released in 2015.<br><br>"
                        "It provides an efficient, powerful and flexible approach to developing web APIs, and has been compared and contrasted with REST and other web service architectures. It allows clients to define the structure of the data required, and exactly the same structure of the data is returned from the server, therefore preventing excessively large amounts of data from being returned, but this has implications for how effective web caching of query results can be. The flexibility and richness of the query language also adds complexity that may not be worthwhile for simple APIs. It consists of a type system, query language and execution semantics, static validation, and type introspection.<br><br>"
                        "GraphQL supports reading, writing (mutating) and subscribing to changes to data (realtime updates).",
                        severity="Information", confidence="Firm", issuebg="Not posing any imminent security risk.",
                        rembg="<ul><li><a href='https://graphql.org/'>GraphQL</a></li></ul>",
                        remdet=""
                    )])

            for check in CONSOLE_CHECKS:
                # look for matches of our passive check grep string
                matches = self._get_matches(result.getResponse(), bytearray(check))
                if len(matches) != 0:
                    # report the issue
                    issues.extend([_CustomScanIssue(
                        http_service=result.getHttpService(),
                        url=self._helpers.analyzeRequest(result).getUrl(),
                        http_messages=[self._callbacks.applyMarkers(result, None, matches)],
                        name="Exposed GraphQL Development Console",
                        detail="GraphQL is a query language for APIs and a runtime for fulfilling queries with existing data.<br><br>"
                        "<b>GraphiQL/GraphQL Playground</b> are in-browser tools for writing, validating, and testing GraphQL queries.<br><br>"
                        "The response contains the following string: <b>%s</b>." % check,
                        severity="Low", confidence="Firm", issuebg="Not posing any imminent security risk.",
                        rembg="<ul>"
                        "<li><a href='https://graphql.org/'>GraphQL</a></li>"
                        "<li><a href='https://github.com/graphql/graphiql'>GraphiQL</a></li>"
                        "<li><a href='https://github.com/prisma/graphql-playground'>GraphQL Playground</a></li>"
                        "</ul>",
                        remdet="Remove the GraphQL development console from web-application in a production stage.<br><br>"
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
        """
        This method is called when multiple issues are reported for the same URL
        path by the same extension-provided check. The value we return from this
        method determines how/whether Burp consolidates the multiple issues
        to prevent duplication

        Do not report same issues on the same path

        :param existingIssue: an issue we have already saved
        :param newIssue: an issue we are gonna insert
        :return: 0 if the issue as to be inserted, -1 otherwise
        """

        if (existingIssue.getHttpMessages()[0].getHttpService().getHost() == newIssue.getHttpMessages()[
            0].getHttpService().getHost()) and (
                existingIssue.getHttpMessages()[0].getHttpService().getPort() == newIssue.getHttpMessages()[
            0].getHttpService().getPort()):
            return -1
        else:
            return 0