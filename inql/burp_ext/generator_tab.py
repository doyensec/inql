from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import json

from burp import ITab

from inql.actions.sendto import SendToAction
from inql.burp_ext.contextual import BurpHTTPMutator as HTTPMutator, OmniMenuItem
from inql.actions.setcustomheader import CustomHeaderSetterAction
from inql.widgets.generator import GeneratorPanel


class GeneratorTab(ITab):
    """
    Java GUI
    """
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self.disable_http2()

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
        repeater_post_urlencoded_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers,
                                              text="Send to Repeater (POST - Body URLEncoded)")
        repeater_post_formdata_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers,
                                              text="Send to Repeater (POST - Body form-data)")
        graphiql_omnimenu = OmniMenuItem(callbacks=self._callbacks, helpers=self._helpers, text="Send to GraphiQL")

        http_mutator = HTTPMutator(
            callbacks=self._callbacks, helpers=self._helpers, overrideheaders=overrideheaders)
        self.http_mutator = http_mutator

        repeater_sender = SendToAction(omnimenu=repeater_omnimenu, has_host=http_mutator.has_host,
                                       send_to=http_mutator.send_to_repeater)
        repeater_get_sender = SendToAction(omnimenu=repeater_get_omnimenu, has_host=http_mutator.has_host,
                                           send_to=http_mutator.send_to_repeater_get_query)
        repeater_post_urlencoded_sender = SendToAction(omnimenu=repeater_post_urlencoded_omnimenu, has_host=http_mutator.has_host,
                                            send_to=http_mutator.send_to_repeater_post_urlencoded_body)
        repeater_post_form_data_sender = SendToAction(omnimenu=repeater_post_formdata_omnimenu, has_host=http_mutator.has_host,
                                            send_to=http_mutator.send_to_repeater_post_form_data_body)
        graphiql_sender = SendToAction(omnimenu=graphiql_omnimenu, has_host=http_mutator.has_host,
                                       send_to=http_mutator.send_to_graphiql)

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
                repeater_post_urlencoded_sender,
                repeater_post_form_data_sender,
                graphiql_sender,
                custom_header_setter],
            restore=restore,
            proxy=proxy,
            http_mutator=http_mutator,
            texteditor_factory=self._callbacks.createTextEditor
        )
        self._callbacks.customizeUiComponent(self.panel.this)
        return self.panel.this

    def disable_http2(self):
        try:
            print("Jython does not support HTTP/2 at the current stage: disabling it!")
            j = json.loads(self._callbacks.saveConfigAsJson())
            j['project_options']['http']['http2']['enable_http2'] = False
            self._callbacks.loadConfigFromJson(json.dumps(j))
        except Exception as ex:
            print("Cannot disable HTTP/2! %s" % ex)

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

    def stop(self):
        self.http_mutator.stop()