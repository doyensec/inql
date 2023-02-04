import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

try:
    from BaseHTTPServer import HTTPServer
except ImportError:
    from http.server import HTTPServer

try:
    import urllib.request as urllib_request # for Python 3
except ImportError:
    import urllib2 as urllib_request # for Python 2 and Jython

import errno
import json
import threading
import logging

from java.awt.event import ActionListener


from inql.actions.browser import URLOpener
from inql.grapiql_request_handler import run_http_server

LISTENING_PORT = 0xD09e115ec % (2 ** 16)
LISTENING_PORT_FALLBACK = 20

# building the logger
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.DEBUG)


class SendToAction(ActionListener):
    """
    Class represeintg the action of sending something to BURP Repeater
    """
    def __init__(self, omnimenu, has_host, send_to):
        self._has_host = has_host
        self._send_to = send_to
        self._omnimenu = omnimenu
        self._omnimenu.add_action_listener(self)
        self.menuitem = self._omnimenu.menuitem
        self._host = None
        self._payload = None
        self._fname = None

    def actionPerformed(self, e):
        """
        Overrides ActionListener behaviour. Send current query to repeater.

        :param e: unused
        :return: None
        """
        self._send_to(self._host, self._payload)

    def ctx(self, host=None, payload=None, fname=None):
        """
        When a fname is specified and is a query file or a request is selected in the other tabs,
        enables the context menu to send to repeater tab

        :param host: should be not null
        :param payload: should be not null
        :param fname: should be not null
        :return: None
        """
        self._host = host
        self._payload = payload
        self._fname = fname

        if not self._fname.endswith('.query'):
            self._omnimenu.set_enabled(False)
            return

        if self._has_host(host):
            self._omnimenu.set_enabled(True)
        else:
            self._omnimenu.set_enabled(False)

class HTTPMutator(object):
    """
    An implementation of an HTTPMutater which employs the Burp Utilities to enhance the requests
    """
    def __init__(self, overrideheaders=None, requests=None, stub_responses=None):
        self._requests = requests if requests is not None else {}
        self._overrideheaders = overrideheaders if overrideheaders is not None else {}
        self._overrideheaders = overrideheaders if overrideheaders is not None else {}
        self._index = 0
        self._stub_responses = stub_responses if stub_responses is not None else {}

        # Register GraphIQL Server
        for attempt in range(LISTENING_PORT_FALLBACK + 1):
            try:
                port = LISTENING_PORT + attempt
                self._server = HTTPServer(('127.0.0.1', port), run_http_server(self, self._requests, self._overrideheaders))
                logging.info("Starting HTTP server on http://127.0.0.1://%s" % port)
                break
            except Exception as e:
                # If the static port isn't available (probably another Burp instance running in background), take the next port
                if e.errno in (errno.EADDRINUSE, errno.EADDRNOTAVAIL):
                    continue
                else:
                    raise
        else:
            raise Exception("No available ports for running embedded web server (tried ports from %s to %s)" %
                (LISTENING_PORT, port))
        t = threading.Thread(target=self._server.serve_forever)
        #t.daemon = True
        t.start()


    def get_graphiql_target(self, server_port, host=None, query=None, variables=None):

        req = self._requests[host]
        target_url = "%s://%s/" % (req['scheme'], req['host'])
        base_url = "http://localhost:%s/%s" % (server_port, target_url)
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
  
    def get_stub_response(self, host):
        return self._stub_responses[host] if host in self._stub_responses else None

    def set_stub_response(self, host, payload):
        self._stub_responses[host] = payload

    def send_to_graphiql(self, host, payload):
        logging.debug("Send to GraphiQL triggered")
        content = json.loads(payload)
        if isinstance(content, list):
            content = content[0]


        URLOpener().open(self.get_graphiql_target(
            self._server.server_port, host,
            content['query'] if 'query' in content else None,
            content['variables'] if 'variables' in content else None))

    def stop(self):
        self._server.shutdown()
        self._server.socket.close()