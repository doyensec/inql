from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from burp import ITab

from inql.actions.sendtorepeater import RepeaterSenderAction
from inql.actions.setcustomheader import CustomHeaderSetterAction
from inql.widgets.tab import GraphQLPanel


class GraphQLTab(ITab):
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
        repeater_sender = RepeaterSenderAction(callbacks=self._callbacks, helpers=self._helpers, text="Send to Repeater", overrideheaders=overrideheaders)
        custom_header_setter = CustomHeaderSetterAction(overrideheaders=overrideheaders, text="Set Custom Header")
        try:
            restore = self._callbacks.loadExtensionSetting(GraphQLPanel.__name__)
        except Exception as ex:
            print("Cannot restore state! %s" % ex)
            restore = None
        self.panel = GraphQLPanel(
            actions=[
                repeater_sender,
                custom_header_setter],
            restore=restore)
        self._callbacks.customizeUiComponent(self.panel.this)
        return self.panel.this

    def save(self):
        """
        Save Extension State before exiting
        :return: None
        """
        try:
            self._callbacks.saveExtensionSetting(self.panel.__class__.__name__, self.panel.state())
        except:
            print("Cannot save state!")