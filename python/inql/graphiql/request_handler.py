# coding: utf-8
import json
import re
from io import BytesIO

from BaseHTTPServer import BaseHTTPRequestHandler
from urlparse import urlparse

from ..logger import log
from ..utils.http import send_request
from .template import graphiql_template

# TODO: Review file once other functionality has been finalized
# pylint: skip-file


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

def run_http_server(http_mutator, requests, overrideheaders):
    class GraphQLRequestHandler(BaseHTTPRequestHandler):

        @property
        def graphiql_html(self):
            return graphiql_template(address=self.path.split('?')[0],
                                        burp=not not http_mutator)

        @property
        def allowed_origin(self):
            if not hasattr(self, '_allowed_origin'):
                self._allowed_origin = re.compile(r'https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$')
            return self._allowed_origin

        def local_log(self):
            log.debug("%s %s" % (self.command, self.path))

        def send_cors_headers(self):
            # Only allow cross-origin requests from localhost
            request_origin = self.headers.getheader('Origin', '*')
            response_origin = request_origin if self.allowed_origin.match(request_origin) else 'http://localhost'

            self.send_header('Access-Control-Allow-Origin', response_origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS')
            self.send_header("Access-Control-Allow-Headers", "Content-Type")


        def do_OPTIONS(self):
            self.local_log()

            self.send_response(200, "ok")
            self.send_cors_headers()
            self.end_headers()

        def do_GET(self):
            self.local_log()

            if self.path == '/favicon.ico':
                self.send_error(404, 'Not found')
                return
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(self.graphiql_html.encode())
            return

        def do_POST(self):
            self.local_log()

            try:
                content_len = int(self.headers.getheader('content-length', 0))
            except AttributeError:  # python3 has not the getheader type, use get instead
                content_len = int(self.headers.get('Content-Length'))

            host = None
            body = None
            try:
                idx = self.path.find('?')
                if idx != -1:
                    endpoint = self.path[1:idx]
                else:
                    endpoint = self.path[1:]

                url = urlparse(endpoint)
                if (url.scheme == "https" and url.port == 443) or (url.scheme == "http" and url.port == 80):
                    host = url.hostname
                else:
                    host = url.netloc

                self.headers['Host'] = host
                body = self.rfile.read(content_len)

                # Send request through Burp
                req = requests.get(host, None)
                if not req:
                    return

                request = HTTPRequest(req['body'])

                headers = []
                for k, v in request.headers:
                    if k.lower() != 'content-length':
                        headers[k] = v

                for k, v in overrideheaders.get(host, {}):
                    headers[k] = v

                contents = send_request(endpoint, headers, 'POST', body)

                jres = json.loads(contents)
                if 'errors' in jres and len(jres['errors']) > 0 and "IntrospectionQuery" in body:
                    raise Exception("IntrospectionQuery request contains errors")

                self.send_response(200)
                self.send_cors_headers()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()

                self.wfile.write(contents.encode())
            except Exception as ex:
                log.error("An exception occured during POST: %s" % ex)
                if host and http_mutator and http_mutator.get_stub_response(host) and "IntrospectionQuery" in body:
                    self.send_response(200)
                    self.send_cors_headers()
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(http_mutator.get_stub_response(host))
                    return
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()

                try:
                    # Try to get the 400 page error content since it is used by the GraphiQL Console
                    self.wfile.write(ex.read())
                except:
                    pass
            return

        def do_PUT(self):
            self.local_log()

            try:
                content_len = int(self.headers.getheader('content-length', 0))
            except AttributeError:  # python3 has not the getheader type, use get instead
                content_len = int(self.headers.get('Content-Length'))

            body = self.rfile.read(content_len)
            url = urlparse(self.path[1:])
            if url.scheme == "https" and url.port == 443 or url.scheme == "http" and url.port == 80:
                host = url.hostname
            else:
                host = url.netloc
            http_mutator.send_to_repeater(host, body)

            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            return

    return GraphQLRequestHandler
