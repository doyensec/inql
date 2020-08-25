import re
import os
import time
import threading
import ssl
import json

try:
    import urllib.request as urllib_request # for Python 3
except ImportError:
    import urllib2 as urllib_request # for Python 2 and Jython

try:
    from urllib.parse import urlparse # for Python 3
except ImportError:
    from urlparse import urlparse # for Python 2 and Jython

try:
    from BaseHTTPServer import BaseHTTPRequestHandler
except ImportError:
    from http.server import BaseHTTPRequestHandler

from io import BytesIO

def string_join(*ss):
    """
    String joins with arbitrary lengthy parameters

    :param ss: strings to be joined
    :return: strings joined
    """
    return "".join(ss)


def mkdir_p(path):
    """
    Create Directory if it does not exist, exit otherwise
    :param path:
    :return:
    """
    try:
        os.makedirs(path)
    except:
        if os.path.isdir(path):
            pass
        else:
            raise


def wrap_open(method, exceptions = (OSError, IOError)):
    """Wrap Open method in order to create containing directories if they does not exist"""
    def fn(*args, **kwargs):
        try:
            mkdir_p(os.path.dirname(args[0]))
            return method(*args, **kwargs)
        except exceptions:
            sys.exit('Can\'t open \'{0}\'. Error #{1[0]}: {1[1]}'.format(args[0], sys.exc_info()[1].args))

    return fn


open = wrap_open(open)


def inherits_popup_menu(element):
    """
    Inherits popup menu on each and every child widgets.

    :param element: current widget.
    :return: None
    """
    element.setInheritsPopupMenu(True)
    try:
        for e in element.getComponents():
            inherits_popup_menu(e)
    except:
        pass


class AttrDict(dict):
    """
    HACK: this class will generate a class object with fields from a dict
    """
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


def override_headers(http_header, overrideheaders):
    """
    Overrides headers with the defined overrides.

    :param http_header: an HTTP header content
    :param overrideheaders: an overrideheaders object.
    :return: a new overridden headers string
    """
    ree = [(
        re.compile("^%s\s*:\s*[^\n]+$" % re.escape(header), re.MULTILINE),
        "%s: %s" % (header, val))
        for (header, val) in overrideheaders]
    h = http_header
    for find, replace in ree:
        hn = re.sub(find, replace, h)
        if hn == h:
            h = "%s\n%s" % (hn, str(replace))
        else:
            h = hn

    return h


def nop_evt(evt):
    """
    Do nothing on events

    :param evt: ignored
    :return: None
    """
    pass


def nop():
    """
    Do nothing

    :return: None
    """
    pass


stop_watch = False


def stop():
    global stop_watch
    stop_watch = True


def watch(execute=nop, interval=60):
    global stop_watch
    def async_run():
        try:
            while not stop_watch:
                execute()
                time.sleep(interval)
                sys.stdout.flush()
                sys.stderr.flush()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()

    t = threading.Thread(target=async_run)
    t.start()


def run_async(execute=nop):
    def async_run():
        try:
            execute()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
    threading.Thread(target=async_run).start()


def run_timeout(execute, timeout):
    def async_run():
        try:
            execute()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
    t = threading.Thread(target=async_run)
    t.daemon = True
    t.start()
    t.join(timeout=timeout)


def make_http_handler(http_mutator=None):
    class GraphQLRequestHandler(BaseHTTPRequestHandler):
        def graphiql_page(self, address, extrascript=""):
            """
            Return a graphiql console page given a domain
            :param listenin_on: address on which the graphiql server proxy is listening on
            :param domain: input domain on which to perform queries
            :return: a string representing the graphiql page
            """
            return """<html>
        <head>
          <title>InQL GraphiQL Console</title>
          <link href="https://unpkg.com/graphiql/graphiql.min.css" rel="stylesheet" />
        </head>
        <body style="margin: 0;">
          <div id="graphiql" style="height: 100vh;"></div>

          <script
          crossorigin
          src="https://unpkg.com/react/umd/react.production.min.js"
          ></script>
          <script
          crossorigin
          src="https://unpkg.com/react-dom/umd/react-dom.production.min.js"
          ></script>
          <script
          crossorigin
          src="https://unpkg.com/graphiql/graphiql.min.js"
          ></script>

          <script>

            /**
             * This GraphiQL example illustrates how to use some of GraphiQL's props
             * in order to enable reading and updating the URL parameters, making
             * link sharing of queries a little bit easier.
             *
             * This is only one example of this kind of feature, GraphiQL exposes
             * various React params to enable interesting integrations.
             */

              // Parse the search string to get url parameters.
              var address = "%s";
              var search = window.location.search;
              var parameters = {};
              search.substr(1).split('&').forEach(function (entry) {
                var eq = entry.indexOf('=');
                if (eq >= 0) {
                  parameters[decodeURIComponent(entry.slice(0, eq))] =
                  decodeURIComponent(entry.slice(eq + 1));
                }
              });

            // if variables was provided, try to format it.
            if (parameters.variables) {
              try {
                parameters.variables =
                JSON.stringify(JSON.parse(parameters.variables), null, 2);
              } catch (e) {
                    // Do nothing, we want to display the invalid JSON as a string, rather
                    // than present an error.
                  }
                }

            // When the query and variables string is edited, update the URL bar so
            // that it can be easily shared
            function onEditQuery(newQuery) {
              parameters.query = newQuery;
              updateURL();
            }

            function onEditVariables(newVariables) {
              parameters.variables = newVariables;
              updateURL();
            }

            function onEditOperationName(newOperationName) {
              parameters.operationName = newOperationName;
              updateURL();
            }

            function updateURL() {
              var newSearch = '?' + Object.keys(parameters).filter(function (key) {
                return Boolean(parameters[key]);
              }).map(function (key) {
                return encodeURIComponent(key) + '=' +
                encodeURIComponent(parameters[key]);
              }).join('&');
              history.replaceState(null, null, newSearch);
            }

            const graphQLFetcher = graphQLParams =>
            fetch(address, {
              method: 'post',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(graphQLParams),
            })
            .then(response => response.json())
            .catch(() => response.text());
            ReactDOM.render(
              React.createElement(GraphiQL, {
                fetcher: graphQLFetcher,
                query: parameters.query,
                variables: parameters.variables,
                operationName: parameters.operationName,
                onEditQuery: onEditQuery,
                onEditVariables: onEditVariables,
                onEditOperationName: onEditOperationName
              }),
              document.getElementById('graphiql'),
            );
            while (document.querySelector('.title') == null) {
                // wait for the title to be something
            }
            document.querySelector('.title').innerHTML = '<a href="https://github.com/doyensec/inql"><img src="https://github.com/doyensec/inql/blob/master/docs/inql.png?raw=true" style="display: block; height:6em; z-index: 10; position: relative"></img></a>';
            %s
          </script>
        </body>
        </html>""" % (address, extrascript)

        # Handler for the GET requests
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Send the html message
            if http_mutator:
                page = self.graphiql_page(self.path, extrascript="""(function() {
              var toolbar = document.querySelector('.toolbar');
              var sendToRepeater = document.createElement('button');
              sendToRepeater.classList.add('toolbar-button');
              sendToRepeater.innerHTML = 'Send To Repeater';
              sendToRepeater.title = 'Send To Repeater';
              sendToRepeater.setAttribute('aria-invalid', true);
              sendToRepeater.onclick = function() {
                var xhr = new XMLHttpRequest();
                xhr.open("PUT", address, true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                var params = JSON.parse(JSON.stringify(parameters));
                try {
                    params['variables'] = JSON.parse(params['variables']);
                } catch (e) {
                    console.log('Cannot parse parameters');
                }
                xhr.send(JSON.stringify(params));
              }
              toolbar.appendChild(sendToRepeater);
            } ());""")
            else:
                page = self.graphiql_page(self.path)

            self.wfile.write(page.encode())
            return

        def do_POST(self):
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
                if url.scheme == "https" and url.port == 443 or url.scheme == "http" and url.port == 80:
                    host = url.hostname
                else:
                    host = url.netloc
                self.headers['Host'] = host
                body = self.rfile.read(content_len)
                if not http_mutator:
                    request = urllib_request.Request(endpoint, body, headers=self.headers)
                else:
                    request = http_mutator.build_python_request(endpoint, host, body)

                contents = urlopen(request, verify=not ('http_proxy' in os.environ or 'https_proxy' in os.environ)).read()

                jres = json.loads(contents)
                if 'errors' in jres and len(jres['errors']) > 0 and "IntrospectionQuery" in body:
                    raise Exception("IntrospectionQuery request contains errors")

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()

                self.wfile.write(contents)
            except Exception as ex:
                if host and http_mutator and http_mutator.get_stub_response(host) and "IntrospectionQuery" in body:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(http_mutator.get_stub_response(host))
                    return
                print(ex)
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
            try:
                content_len = int(self.headers.getheader('content-length', 0))
            except AttributeError:  # python3 has not the getheader type, use get instead
                content_len = int(self.headers.get('Content-Length'))

            if http_mutator:
                body = self.rfile.read(content_len)
                url = urlparse(self.path[1:])
                if url.scheme == "https" and url.port == 443 or url.scheme == "http" and url.port == 80:
                    host = url.hostname
                else:
                    host = url.netloc
                http_mutator.send_to_repeater(host, body)
            else:
                print(self.path)
                print(self.rfile.read(content_len))

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            return
    return GraphQLRequestHandler

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

try:
    import sys
    from javax.net.ssl import TrustManager, X509TrustManager
    from jarray import array
    from javax.net.ssl import SSLContext


    class TrustAllX509TrustManager(X509TrustManager):

        # Define a custom TrustManager which will blindly
        # accept all certificates
        def checkClientTrusted(self, chain, auth):
            pass

        def checkServerTrusted(self, chain, auth):
            pass

        def getAcceptedIssuers(self):
            return None


    # Create a static reference to an SSLContext which will use
    # our custom TrustManager
    trust_managers = array([TrustAllX509TrustManager()], TrustManager)
    TRUST_ALL_CONTEXT = SSLContext.getInstance("SSL")
    TRUST_ALL_CONTEXT.init(None, trust_managers, None)

    # Keep a static reference to the JVM's default SSLContext for restoring
    # at a later time
    DEFAULT_CONTEXT = SSLContext.getDefault()
    if 'create_default_context' not in dir(ssl):
        SSLContext.setDefault(TRUST_ALL_CONTEXT)
except:
    pass

def urlopen(request, verify):
    ctx = None
    if 'create_default_context' in dir(ssl):
        ctx = ssl.create_default_context()
    elif 'SSLContext' in dir(ssl) and 'PROTOCOL_TLSv1' in dir(ssl):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    if not verify and ctx:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib_request.urlopen(request, context=ctx)
    else:
        return urllib_request.urlopen(request)


def _recursive_name_get(obj):
    try:
        return obj['name'] or _recursive_name_get(obj['ofType'])
    except KeyError:
        return False


def _recursive_kind_of(obj, target):
    try:
        return obj['kind'] == target or _recursive_kind_of(obj['ofType'], target)
    except KeyError:
        return False
    except TypeError:
        return False

def is_query(body):
    # FIXME: handle urlencoded requests too in the future
    try:
        content = json.loads(body)
        if not isinstance(content, list):
            content = [content]

        ret = all(['query' in c or 'operationName' in c
                    for c in content])
        return ret
    except:
        return False

def simplify_introspection(data):
    """
    Generates a simplified introspection object based on an introspection query.
    This utility function is after used by many of the generators.

    # Parsing JSON response/file structure as follows
    # data
    #   __schema
    #       directives
    #       mutationType
    #       queryType
    #       subscriptionType
    #       types (kind, name, description)
    #              name (RootQuery, RootMutation, Subscriptions, [custom] OBJECT)
    #              fields
    #                     name (query names)
    #                     args
    #                            name (args names)
    #                            type
    #                                   name (args types)

    :type data: an introspection query dict
    """

    output = {}
    output['schema'] = {}
    schema = data['data']['__schema']

    # Get the Root query type
    if schema['queryType'] and 'name' in schema['queryType']:
        output['schema']['query'] = {
            "type": schema['queryType']['name'],
            "array": False,
            "required": False
        }

    # Get the Root subscription type
    if schema['subscriptionType'] and 'name' in schema['subscriptionType']:
        output['schema']['subscription'] = {
            "type": schema['subscriptionType']['name'],
            "array": False,
            "required": False
        }

    # Get the Root mutation type
    if schema['mutationType'] and 'name' in schema['mutationType']:
        output['schema']['mutation'] = {
            "type": schema['mutationType']['name'],
            "array": False,
            "required": False
        }

    # Go over all the fields and simplify the JSON
    output['type'] = {}
    for type in schema['types']:
        if type['name'][0:2] == '__': continue
        if type['kind'] == 'OBJECT':
            output['type'][type['name']] = {}
            if type['fields']:
                for field in type['fields']:
                    output['type'][type['name']][field['name']] = {
                        "type": _recursive_name_get(field['type']),
                        "required": field['type']['kind'] == 'NON_NULL',
                        "array": _recursive_kind_of(field['type'], 'LIST'),
                    }
                    if field['args']:
                        output['type'][type['name']][field['name']]["args"] = {}
                        for arg in field['args']:
                            output['type'][type['name']][field['name']]['args'][arg['name']] = {
                                "type": _recursive_name_get(arg['type']),
                                "required": arg['type']['kind'] == 'NON_NULL',
                                "array": _recursive_kind_of(arg['type'], 'LIST'),
                            }
                            if arg['defaultValue'] != None:
                                output['type'][type['name']][field['name']]['args'][arg['name']]['default'] = arg[
                                    'defaultValue']
            if type['interfaces']:
                output['type'][type['name']]['__implements'] = {}
                for iface in type['interfaces']:
                    output['type'][type['name']]['__implements'][iface['name']] = {}

            if 'type' not in output['type'][type['name']] and 'args' in output['type'][type['name']]:
                output['type'][type['name']]["type"] = output['type'][type['name']]["args"]["type"]


    # Get all the Enums
    output['enum'] = {}
    for type in schema['types']:
        if type['name'][0:2] == '__': continue
        if type['kind'] == 'ENUM':
            output['enum'][type['name']] = {}
            for v in type['enumValues']:
                output['enum'][type['name']][v['name']] = {}

    # Get all the Scalars
    output['scalar'] = {}
    for type in schema['types']:
        if type['name'][0:2] == '__': continue
        if type['kind'] == 'SCALAR' and type['name'] not in ['String', 'Int', 'Float', 'Boolean', 'ID']:
            output['scalar'][type['name']] = {}

    # Get all the inputs
    output['input'] = {}
    for type in schema['types']:
        if type['name'][0:2] == '__': continue
        if type['kind'] == 'INPUT_OBJECT':
            output['input'][type['name']] = {}
            if type['inputFields']:
                for field in type['inputFields']:
                    output['input'][type['name']][field['name']] = {
                        "type": _recursive_name_get(field['type']),
                        "required": field['type']['kind'] == 'NON_NULL',
                        "array": _recursive_kind_of(field['type'], 'LIST'),
                    }

    # Get all the unions
    output['union'] = {}
    for type in schema['types']:
        if type['name'][0:2] == '__': continue
        if type['kind'] == 'UNION':
            output['union'][type['name']] = {}
            for v in type['possibleTypes']:
                output['union'][type['name']][v['name']] = {}

    # Get all the interfaces
    output['interface'] = {}
    for type in schema['types']:
        if type['name'][0:2] == '__': continue
        if type['kind'] == 'INTERFACE':
            output['interface'][type['name']] = {}
            if type['fields']:
                for field in type['fields']:
                    output['interface'][type['name']][field['name']] = {
                        "type": _recursive_name_get(field['type']),
                        "required": field['type']['kind'] == 'NON_NULL',
                        "array": _recursive_kind_of(field['type'], 'LIST'),
                    }
                    if field['args']:
                        output['interface'][type['name']][field['name']]["args"] = {}
                        for arg in field['args']:
                            output['interface'][type['name']][field['name']]['args'][arg['name']] = {
                                "type": _recursive_name_get(arg['type']),
                                "required": arg['type']['kind'] == 'NON_NULL',
                                "array": _recursive_kind_of(arg['type'], 'LIST'),
                            }
                            if arg['defaultValue'] != None:
                                output['interface'][type['name']][field['name']]['args'][arg['name']]['default'] = arg[
                                    'defaultValue']
            if 'type' not in output['interface'][type['name']] and 'args' in output['interface'][type['name']]:
                output['interface'][type['name']]["type"] = output['interface'][type['name']]["args"]["type"]

    return output


def raw_request(request):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in
    this function because it is programmed to be pretty
    printed and may differ from the actual request.
    """
    headers = request.headers.copy()
    if 'Connection' not in headers:
        headers['Connection'] = 'close'
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0'
    if 'Accept-Encoding' not in headers:
        headers['Accept-Encoding'] = 'gzip, deflate'
    url = urlparse(request.get_full_url())
    headers['Host'] = url.netloc
    path = url.path if len(url.path) else '/'

    return '{}\r\n{}\r\n\r\n{}'.format(
        request.get_method() + ' ' + path + ' HTTP/1.1',
        '\r\n'.join('{}: {}'.format(k, v) for k, v in headers.items()),
        request.data if request.data else '',
    )