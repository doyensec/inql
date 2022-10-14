from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import json
import sys
from javax.swing import JPanel, JSplitPane, JLabel, JComboBox, JButton, BoxLayout, Box, JTextField, JTable, JScrollPane, JTabbedPane
from java.awt import BorderLayout, Dimension
from burp import ITab
from .attacker_history_log import AttackerHistoryLog
from .attacker_history_viewer import AttackerHistoryViewer
from .attacker_request import AttackerRequest

class AttackerTab(ITab):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self.disable_http2_ifbogus()

    def getTabCaption(self):
        """The name of the custom tab."""
        return "InQL Attacker"

    def getUiComponent(self):
        """Factory, should return a new tab."""
        # Request editor & buttons (left pane)
        request_pane = AttackerRequest(self._callbacks)

        # Request/response views (top right pane)
        history_viewer = AttackerHistoryViewer(self._callbacks.createMessageEditor)

        # Log entries (bottom right pane)
        history_log = AttackerHistoryLog(self._callbacks, history_viewer)

        # Top level pane
        return JPanel().add(JSplitPane(
            # Split between left and right
            JSplitPane.HORIZONTAL_SPLIT,
            leftComponent = request_pane.render(),
            rightComponent = JSplitPane(
                # Split within the right pane (top / bottom)
                JSplitPane.VERTICAL_SPLIT,
                leftComponent = history_log.render(),
                rightComponent = history_viewer.render()
            )
        ))

    def disable_http2_ifbogus(self):
        try:
            _, major, minor = self._callbacks.getBurpVersion()
            if not (int(major) >= 2021 and float(minor) >= 8):
                print("Jython does not support HTTP/2 on Burp <= 2021.8: disabling it!")
                j = json.loads(self._callbacks.saveConfigAsJson())
                j['project_options']['http']['http2']['enable_http2'] = False
                self._callbacks.loadConfigFromJson(json.dumps(j))
        except Exception as ex:
            print("Cannot disable HTTP/2! %s" % ex)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()