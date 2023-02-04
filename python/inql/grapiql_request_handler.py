try:
    from BaseHTTPServer import BaseHTTPRequestHandler
except ImportError:
    from http.server import BaseHTTPRequestHandler

try:
    import urllib.request as urllib_request # for Python 3
except ImportError:
    import urllib2 as urllib_request # for Python 2 and Jython

try:
    from urllib.parse import urlparse # for Python 3
except ImportError:
    from urlparse import urlparse # for Python 2 and Jython

from io import BytesIO

import re
import os
import json
import re
import logging
from .templates import graphiql_template
from inql.utils import urlopen


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
                self._allowed_origin = re.compile('https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$')
            return self._allowed_origin

        def log(self):
            logging.debug("%s %s" % (self.command, self.path))

        def send_cors_headers(self):
            # Only allow cross-origin requests from localhost
            request_origin = self.headers.getheader('Origin', '*')
            response_origin = request_origin if self.allowed_origin.match(request_origin) else 'http://localhost'

            self.send_header('Access-Control-Allow-Origin', response_origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS')
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def build_python_request(self, endpoint, host, payload):
            logging.debug("Building request for GraphiQL with custom headers")
            req = requests[host]
            if req:
                original_request = HTTPRequest(req['body'])
                del original_request.headers['Content-Length']

                # Building the dictionary with the original headers
                original_headers = {}
                for x in original_request.headers:
                    original_headers[x] = original_request.headers[x]

                # avoid errors later if host was never added to the custo headers
                if host not in overrideheaders:
                    logging.debug("No custom header found for %s", host)
                    overrideheaders[host] = []

                # adding (changing) the custom headers
                for elem in overrideheaders[host]:
                    original_headers[elem[0].encode('utf-8')] = elem[1].encode('utf-8') 

                return urllib_request.Request(endpoint, payload, headers=original_headers)

        def do_OPTIONS(self):
            self.log()

            self.send_response(200, "ok")
            self.send_cors_headers()
            self.end_headers()
        
        def do_GET(self):
            self.log()

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
            self.log()

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
                
                
                request = self.build_python_request(endpoint, host, body)

                contents = urlopen(request, verify=not ('http_proxy' in os.environ or 'https_proxy' in os.environ)).read()

                jres = json.loads(contents)
                if 'errors' in jres and len(jres['errors']) > 0 and "IntrospectionQuery" in body:
                    raise Exception("IntrospectionQuery request contains errors")

                self.send_response(200)
                self.send_cors_headers()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()

                self.wfile.write(contents.encode())
            except Exception as ex:
                logging.error("An exception occured during POST: %s" % ex)
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
            self.log()

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