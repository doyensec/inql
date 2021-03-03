from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import json

from burp import ITab

from inql.actions.sendto import GenericSendToAction, OmniMenuItem, GraphiQLSenderAction
from inql.actions.sendto import EnhancedHTTPMutator
from inql.actions.setcustomheader import CustomHeaderSetterAction
from inql.widgets.generator import GeneratorPanel


class GeneratorTab(ITab):
    """
    Java GUI
    """
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers

    def getTabCaption(self):
        """
        Override ITab method
        :return: tab name
        """
        return "InQL Scanner"

    def getUiComponent(self):
        """
        Override ITab method
        :return: Tab UI Component
        """
        overrideheaders = {}

        repeater_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers, text="Send to Repeater")
        repeater_get_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers,
                                             text="Send to Repeater (GET - Query Params)")
        repeater_post_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers,
                                              text="Send to Repeater (POST - Body URLEncoded)")
        graphiql_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers, text="Send to GraphiQL")

        http_mutator = EnhancedHTTPMutator(
            callbacks=self._callbacks, helpers=self._helpers, overrideheaders=overrideheaders)

        repeater_sender = GenericSendToAction(omnimenu=repeater_omnimenu, has_host=http_mutator.has_host, send_to=http_mutator.send_to_repeater)
        repeater_get_sender = GenericSendToAction(omnimenu=repeater_get_omnimenu, has_host=http_mutator.has_host, send_to=http_mutator.send_to_repeater_get_query)
        repeater_post_sender = GenericSendToAction(omnimenu=repeater_post_omnimenu, has_host=http_mutator.has_host, send_to=http_mutator.send_to_repeater_post_urlencoded_body)
        graphiql_sender = GraphiQLSenderAction(omnimenu=graphiql_omnimenu, http_mutator=http_mutator)
        custom_header_setter = CustomHeaderSetterAction(overrideheaders=overrideheaders, text="Set Custom Header")
        try:
            restore = self._callbacks.loadExtensionSetting(GeneratorPanel.__name__)
        except Exception as ex:
            print("Cannot restore state! %s" % ex)
            restore = None

        proxy = None

        for request_listener in json.loads(self._callbacks.saveConfigAsJson())["proxy"]["request_listeners"]:
            if request_listener["running"]:
                proxy = "localhost:%s" % request_listener["listener_port"]
                break

        self.panel = GeneratorPanel(
            actions=[
                repeater_sender,
                repeater_get_sender,
                repeater_post_sender,
                graphiql_sender,
                custom_header_setter],
            restore=restore,
            proxy=proxy,
            http_mutator=http_mutator,
            texteditor_factory=self._callbacks.createTextEditor
        )
        self._callbacks.customizeUiComponent(self.panel.this)
        return self.panel.this

    def bring_in_front(self):
        self.panel.this.setAlwaysOnTop(True)
        self.panel.this.setAlwaysOnTop(False)

    def save(self):
        """
        Save Extension State before exiting
        :return: None
        """
        try:
            self._callbacks.saveExtensionSetting(self.panel.__class__.__name__, self.panel.state())
        except:
            print("Cannot save state!")