import json
import threading
from http.server import HTTPServer
from urllib import request as urllib_request
from urllib.parse import urlencode

from inql.actions.browser import URLOpener
from inql.actions.sendto import IProxyListener
from inql.utils import make_http_handler, is_query, HTTPRequest, override_headers, string_join, override_uri, clean_dict


class HTTPMutator(IProxyListener):
    """
    An implementation of an HTTPMutater which employs the Burp Utilities to enhance the requests
    """
    def __init__(self, callbacks=None, helpers=None, overrideheaders=None, requests=None, stub_responses=None):
        self._requests = requests if requests is not None else {}
        self._overrideheaders = overrideheaders if overrideheaders is not None else {}
        self._overrideheaders = overrideheaders if overrideheaders is not None else {}
        self._index = 0
        self._stub_responses = stub_responses if stub_responses is not None else {}

        # Register GraphIQL Server
        self._server = HTTPServer(('127.0.0.1', 0), make_http_handler(self))
        t = threading.Thread(target=self._server.serve_forever)
        #t.daemon = True
        t.start()

        if helpers and callbacks:
            self._helpers = helpers
            self._callbacks = callbacks
            self._callbacks.registerProxyListener(self)
            for r in self._callbacks.getProxyHistory():
                self._process_request(self._helpers.analyzeRequest(r), r.getRequest())


    def _process_request(self, reqinfo, reqbody):
        """
        Process request and extract key values

        :param reqinfo:
        :param reqbody:
        :return:
        """
        url = str(reqinfo.getUrl())
        if is_query(reqbody[reqinfo.getBodyOffset():].tostring()):
            for h in reqinfo.getHeaders():
                if h.lower().startswith("host:"):
                    domain = h[5:].strip()

            method = reqinfo.getMethod()
            try:
                self._requests[domain]
            except KeyError:
                self._requests[domain] = {'POST': None, 'PUT': None, 'GET': None, 'url': None}
            self._requests[domain][method] = (reqinfo, reqbody)
            self._requests[domain]['url'] = url

    def processProxyMessage(self, messageIsRequest, message):
        """
        Implements IProxyListener method

        :param messageIsRequest: True if BURP Message is a request
        :param message: message content
        :return: None
        """
        if self._helpers and self._callbacks and messageIsRequest:
            self._process_request(self._helpers.analyzeRequest(message.getMessageInfo()),
                                  message.getMessageInfo().getRequest())

    def get_graphiql_target(self, server_port, host=None, query=None, variables=None):
        base_url = "http://localhost:%s/%s" % (server_port, self._requests[host]['url'])
        arguments = ""
        if query or variables:
            arguments += '?'
            args = []
            if host:
                args.append("query=%s" % urllib_request.quote(query))
            if variables:
                args.append("variables=%s" % urllib_request.quote(json.dumps(variables)))
            arguments += "&".join(args)

        return base_url + arguments

    def has_host(self, host):
        try:
            self._requests[host]
            return True
        except KeyError:
            return False

    def build_python_request(self, endpoint, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req:
            original_request = HTTPRequest(req[1])
            del original_request.headers['Content-Length']

            # TODO: Implement custom headers in threads. It is not easy to share them with the current architecture.
            return urllib_request.Request(endpoint, payload, headers=original_request.headers)

    def get_stub_response(self, host):
        return self._stub_responses[host] if host in self._stub_responses else None

    def set_stub_response(self, host, payload):
        self._stub_responses[host] = payload

    def send_to_repeater(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            headers = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            headers = override_headers(headers, self._overrideheaders[host])
            repeater_body = StringUtil.toBytes(string_join(
                headers,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring(),
                payload))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL #%s' % self._index)
            self._index += 1

    def send_to_repeater_get_query(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            metadata = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            metadata = override_headers(metadata, self._overrideheaders[host])
            metadata = override_uri(metadata, method="GET", query=urlencode(clean_dict(json.loads(payload))))

            repeater_body = StringUtil.toBytes(string_join(
                metadata,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring()))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL (GET query) #%s' % self._index)
            self._index += 1

    def send_to_repeater_post_urlencoded_body(self, host, payload):
        req = self._requests[host]['POST'] or self._requests[host]['PUT'] or self._requests[host]['GET']
        if req and self._callbacks and self._helpers:
            info = req[0]
            body = req[1]
            nobody = body[:info.getBodyOffset()].tostring()
            rstripoffset = info.getBodyOffset()-len(nobody.rstrip())
            headers = body[:info.getBodyOffset()-rstripoffset].tostring()

            try:
                self._overrideheaders[host]
            except KeyError:
                self._overrideheaders[host] = []

            headers = override_headers(headers, self._overrideheaders[host])
            headers = override_headers(headers, [("Content-Type", "application/x-www-form-urlencoded")])
            headers = override_uri(headers, method="POST")
            repeater_body = StringUtil.toBytes(string_join(
                headers,
                body[info.getBodyOffset()-rstripoffset:info.getBodyOffset()].tostring(),
                urlencode(clean_dict(json.loads(payload)))))

            self._callbacks.sendToRepeater(info.getUrl().getHost(), info.getUrl().getPort(),
                                           info.getUrl().getProtocol() == 'https', repeater_body,
                                          'GraphQL (POST urlencoded) #%s' % self._index)
            self._index += 1

    def send_to_graphiql(self, host, payload):
        content = json.loads(payload)
        if isinstance(content, list):
            content = content[0]

        URLOpener().open(self.get_graphiql_target(
            self._server.server_port, host,
            content['query'] if 'query' in content else None,
            content['variables'] if 'variables' in content else None))