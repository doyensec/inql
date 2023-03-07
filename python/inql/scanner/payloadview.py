# coding: utf-8
import json

from burp.api.montoya.http.HttpService import httpService
from burp.api.montoya.http.message.requests.HttpRequest import httpRequest

from java.awt import BorderLayout

from gqlspection.utils import minimize_query

from ..logger import log
from ..menu.context_menu import SendFromInQL
from ..utils.ui import add_recursive_mouse_listener, byte_array, raw_editor, ui_panel


class ScannerPayloadView(object):
    _node = None

    def __init__(self):
        """Displays the selected query / mutation."""
        log.debug("ScannerPayloadView initiated")
        self.component = ui_panel(0)

        self._editor = raw_editor(read_only=True)
        self.component.add(self._editor.uiComponent(), BorderLayout.CENTER)

        log.debug("ScannerPayloadView done")

    def render(self):
        return self.component

    def load(self, node):
        log.debug("Display %s in payload view.", node)
        self._node = node

        log.debug("Loading file %s into payload view.", node.path)
        with open(node.path, "rb") as f:
            data = f.read()

        self._editor.setContents(byte_array(data))
        log.debug("Succesfully sent bytearray to payload view.")


        if not node.template:
            # Showing howto, there's no need for right click
            return

        log.debug("Generating request body for context menu handlers")
        body = json.dumps({
            "query": minimize_query(data)
            })

        http_service = httpService(node.url)

        with open(node.template) as f:
            _ = f.readline()
            template = f.read()
        request = httpRequest(template).withBody(body).withService(http_service)
        log.debug("Built request for context menu handlers")

        mouse_listener = SendFromInQL(request)
        add_recursive_mouse_listener(mouse_listener, self.component, ScannerPayloadView)
