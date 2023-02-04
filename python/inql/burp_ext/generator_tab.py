from __future__ import print_function

import platform
import logging

# building the logger
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.DEBUG)


if platform.system() != "Java":
    logging.error("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import json
import sys

from burp import ITab

from inql.actions.sendto import SendToAction, HTTPMutator
from inql.burp_ext.contextual import OmniMenuItem
from inql.actions.setcustomheader import CustomHeaderSetterAction
from inql.widgets.generator import GeneratorPanel
from inql.burp_ext.contextual import SendMenuItem


class GeneratorTab(ITab):
    """
    Java GUI

    This class represents the Scanner tab of the burp extension. The main panel is
    build as an instance of "GeneratorPanel" while the components for the context 
    menu are build here. 
    """
    def __init__(self, callbacks, helpers, requests=None, custom_headers=None):
        self._callbacks = callbacks
        self._helpers = helpers
        self._requests = requests
        self._custom_headers = custom_headers
        self.disable_http2_ifbogus()

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
        # overrideheaders = {}

        repeater_omnimenu = OmniMenuItem(
            callbacks=self._callbacks, 
            helpers=self._helpers, 
            text="Send to Repeater")
        repeater_get_omnimenu = OmniMenuItem(
            callbacks=self._callbacks, 
            helpers=self._helpers,
            text="Send to Repeater (GET - Query Params)")
        repeater_post_urlencoded_omnimenu = OmniMenuItem(
            callbacks=self._callbacks, 
            helpers=self._helpers,
            text="Send to Repeater (POST - Body URLEncoded)")
        repeater_post_formdata_omnimenu = OmniMenuItem(
            callbacks=self._callbacks, 
            helpers=self._helpers,
            text="Send to Repeater (POST - Body form-data)")
        graphiql_omnimenu = OmniMenuItem(
            callbacks=self._callbacks, 
            helpers=self._helpers, 
            text="Send to GraphiQL")

        http_mutator = HTTPMutator(
            callbacks=self._callbacks, 
            helpers=self._helpers, 
            requests=self._requests,
            overrideheaders=self._custom_headers)

        self.http_mutator = http_mutator

        # Elements that will compose the context menu

        repeater_sender = SendToAction(
            omnimenu=repeater_omnimenu, 
            has_host=http_mutator.has_host,
            send_to=http_mutator.send_to_repeater)
        repeater_get_sender = SendToAction(
            omnimenu=repeater_get_omnimenu, 
            has_host=http_mutator.has_host,
            send_to=http_mutator.send_to_repeater_get_query)
        repeater_post_urlencoded_sender = SendToAction(
            omnimenu=repeater_post_urlencoded_omnimenu, 
            has_host=http_mutator.has_host,
            send_to=http_mutator.send_to_repeater_post_urlencoded_body)
        repeater_post_form_data_sender = SendToAction(
            omnimenu=repeater_post_formdata_omnimenu, 
            has_host=http_mutator.has_host,
            send_to=http_mutator.send_to_repeater_post_form_data_body)
        graphiql_sender = SendToAction(
            omnimenu=graphiql_omnimenu, 
            has_host=http_mutator.has_host,
            send_to=http_mutator.send_to_graphiql)
        attacker_sender = SendMenuItem(
            callbacks=self._callbacks, 
            label="Attacker", 
            inql_handler=http_mutator.send_to_attacker)

        custom_header_setter = CustomHeaderSetterAction(
            overrideheaders=self._custom_headers, 
            text="Set Custom Header")
        
        try:
            restore = self._callbacks.loadExtensionSetting(GeneratorPanel.__name__)
        except Exception as ex:
            logging.error("Cannot restore state! %s" % ex)
            restore = None

        proxy = None

        for request_listener in json.loads(self._callbacks.saveConfigAsJson())["proxy"]["request_listeners"]:
            if request_listener["running"]:
                proxy = "localhost:%s" % request_listener["listener_port"]
                break

        self.panel = GeneratorPanel(
            # passing the elements composing the context menu
            actions=[
                repeater_sender,
                repeater_get_sender,
                repeater_post_urlencoded_sender,
                repeater_post_form_data_sender,
                graphiql_sender,
                attacker_sender,
                custom_header_setter],
            restore=restore,
            proxy=proxy,
            http_mutator=http_mutator,
            texteditor_factory=self._callbacks.createTextEditor,
            requests=self._requests
        )
        self._callbacks.customizeUiComponent(self.panel.this)
        return self.panel.this

    def disable_http2_ifbogus(self):
        try:
            _, major, minor = self._callbacks.getBurpVersion()
            if not (int(major) >= 2021 and float(minor) >= 8):
                logging.info("Jython does not support HTTP/2 on Burp <= 2021.8: disabling it!")
                j = json.loads(self._callbacks.saveConfigAsJson())
                j['project_options']['http']['http2']['enable_http2'] = False
                self._callbacks.loadConfigFromJson(json.dumps(j))
        except Exception as ex:
            logging.error("Cannot disable HTTP/2! %s" % ex)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()

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
            logging.error("Cannot save state!")

    def stop(self):
        self.http_mutator.stop()