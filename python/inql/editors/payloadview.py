# coding: utf-8
import json
from hashlib import sha256

from burp.api.montoya.http.message.requests.HttpRequest import httpRequest
from burp.api.montoya.ui.editor import EditorOptions
from burp.api.montoya.ui.editor.extension import EditorMode, ExtensionProvidedHttpRequestEditor

from javax.swing import JSplitPane

from gqlspection.utils import minimize_query, pretty_print_graphql

from ..globals import montoya
from ..logger import log
from ..menu.context_menu import SendFromInQL
from ..utils.graphql import is_query
from ..utils.ui import add_recursive_mouse_listener, byte_array


def provideHttpRequestEditor(ctx):
    return EditorPayload(ctx.editorMode() == EditorMode.READ_ONLY)

class EditorPayload(ExtensionProvidedHttpRequestEditor):
    operation_name = ''

    # query = ''
    # vars = {}
    # hash = {'query': None, 'vars': None}
    # errors = {'query': False, 'vars': False}
    # backup = {'query': None, 'vars': None}

    request = None

    def __init__(self, read_only):
        log.debug("montoya editor payload test - init")
        if read_only:
            self.query_editor = montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
            self.vars_editor = montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
        else:
            self.query_editor = montoya.userInterface().createRawEditor()
            self.vars_editor = montoya.userInterface().createRawEditor()

        self.component = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                    self.query_editor.uiComponent(),
                                    self.vars_editor.uiComponent())

        self.component.setDividerLocation(0.5)
        self.component.setResizeWeight(0.75)
        self.component.setOneTouchExpandable(True)

        self.hash = {'query': None, 'vars': None}
        self.errors = {'query': False, 'vars': False}
        self.backup = {'query': None, 'vars': None}

    def uiComponent(self):
        return self.component

    def caption(self):
        log.debug("montoya editor payload test - caption")
        return "GraphQL"

    def isEnabledFor(self, requestResponse):
        log.debug("montoya editor payload test - isEnabledFor")
        body = requestResponse.request().bodyToString()
        if is_query(body):
            log.debug("GraphQL request detected, attaching GraphQL tab to the message editor")
            return True

        log.debug("The request isn't GraphQL, skipping")
        return False

    def isModified(self):
        log.debug("montoya editor payload test - isModified")
        if self.hash['query'] != self._calculate_hash(self.query):
            log.debug("Query has been modified")
            return True
        if self.hash['vars']  != self._calculate_hash(self.vars):
            log.debug("Vars have been modified")
            return True
        log.debug("No modifications detected (%s)", self.hash)
        return True

    # TODO: Not sure how to translate selection, as there are two panes in GraphQL view
    def selectedData(self):
        log.debug("montoya editor payload test - selectedData")
        return None

    def setRequestResponse(self, requestResponse):
        log.debug("montoya editor payload test - setRR")

        request = requestResponse.request()

        body_string = request.bodyToString()
        log.debug("done setting request response (body length: %s)", len(body_string))
        log.debug("body: %s", body_string)

        try:
            body = json.loads(body_string)
            log.debug("Loading new body: %s", body)
        except:
            log.error("Failed to deserialize request body.")

            # Mark errors and backup old values (unless these are repeated errors - don't overwrite backups)
            if not self.errors['query']:
                self.backup['query'] = self.query
            if not self.errors['vars']:
                self.backup['vars'] = self.vars

            self.errors['query'], self.errors['vars'] = True, True
            # Show the message about an error:
            self.query = "There was error during JSON deserialization."
            self.vars = {}
            return

        # Reset backups and error info if JSON parsed successfully
        self.errors['query'], self.errors['vars'] = False, False
        self.backup['query'], self.backup['vars'] = None, None

        if 'operation_name' in body:
            self.operation_name = body['operation_name']
        else:
            self.operation_name = ''

        self.query = body['query']
        # Variables are optional, can be absent, {} and null
        self.vars = body['variables'] if body.get('variables', False) else {}
        log.debug("Loaded new content")

        # Calculate new hashes (note that we need to re-read values as they might have changed due to normalization)
        self.hash['query'] = self._calculate_hash(self.query)
        self.hash['vars']  = self._calculate_hash(self.vars)

        self.request = request.withBody('')

        # Set mouse listener for the context menu
        mouse_listener = SendFromInQL(request, include_scanner=True)
        add_recursive_mouse_listener(mouse_listener, self.component, SendFromInQL)

    # TODO: Parameters aren't processed right due to awkward Montoya API - need to work around this
    def getRequest(self):
        log.debug("montoya editor payload test - getRequest")

        if self.errors['query']:
            if self.hash['query'] != self._calculate_hash(self.query):
                # Query has been modified, assume that user has fixed it
                query = self.query
                self.errors['query'], self.backup['query'] = False, None
            else:
                query = self.backup['query']
        else:
            query = self.query

        log.debug("Error checking")
        if self.errors['vars']:
            if self.hash['vars'] != self._calculate_hash(self.vars):
                variables = self.vars
                self.errors['vars'], self.backup['vars'] = False, None
            else:
                variables = self.backup['vars']
        else:
            variables = self.vars

        body = {"query": query}
        if variables:
            body['variables'] = variables

        if self.operation_name:
            body['operationName'] = self.operation_name

        log.debug("Serializing body")
        serialized_body = json.dumps(body)

        if not self.request:
            request = httpRequest().withBody(serialized_body)
        request = self.request.withBody(serialized_body)
        log.debug("Returning the request: %s", request.toString())

        return request


    def _calculate_hash(self, value):
        log.debug("Calculating hash of '%s'", value)
        if value is None:
            value = {}

        if isinstance(value, dict):
            normalized = json.dumps(value)
        else:
            normalized = value
        return sha256(normalized).digest()


    # If you set a query/vars and then read it back, there's no guarantee it will be the same!
    #
    # self.query = A
    # self.query != A

    # TODO: We're calculating hash twice right now, optimize aglorithm later
    @property
    def query(self):
        try:
            return minimize_query(self.query_editor.getContents().toString())
        except:
            log.error("Failed to parse GraphQL query read from the editor tab")
            return ""

    @query.setter
    def query(self, msg):
        log.debug("Setting new GraphQL query in the editor tab")
        pretty = pretty_print_graphql(msg)
        log.debug("Successfully parsed GraphQL query")
        self.query_editor.setContents(byte_array(pretty))

    @property
    def vars(self):
        string = self.vars_editor.getContents().toString()

        try:
            return json.loads(string)
        except:
            log.error("Failed to deserialize GraphQL variables read from the editor tab: %s", string)
            # TODO: Change this to ask user whether this is ok or not as if the Send
            # button was pressed this would send malformed request
            return {}

    @vars.setter
    def vars(self, msg):
        log.debug("Setting new vars in the editor tab: %s", msg)
        try:
            string = json.dumps(msg, indent=4)
        except:
            log.error("Failed to deserialize GraphQL variables: %s", msg)
            string = '{}'
        log.debug("Setting new vars: %s.", string)
        self.vars_editor.setContents(byte_array(string))
