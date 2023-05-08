# coding: utf-8
from burp import ITab

from javax.swing import JSplitPane

from ..globals import app
from ..utils.pyswing import panel
from ..utils.ui import raw_editor_obsolete
from .history_log import AttackerHistoryLog
from .history_viewer import AttackerHistoryViewer
from .request import AttackerRequest


class AttackerTab(ITab):
    request_pane = None
    history_viewer = None
    history_log = None

    def __init__(self):
        app.attacker = self

    def getTabCaption(self):
        """The name of the custom tab."""
        return "InQL Attacker"

    def getUiComponent(self):
        """Factory, should return a new tab."""
        # Request editor & buttons (left pane)
        self.request_pane = AttackerRequest()

        # Request/response views (top right pane)
        self.history_viewer = AttackerHistoryViewer(raw_editor_obsolete)

        # Log entries (bottom right pane)
        self.history_log = AttackerHistoryLog(self.history_viewer, self.request_pane)

        # Top level pane
        top_panel = panel()
        splitpane = JSplitPane(
            # Split between left and right
            JSplitPane.HORIZONTAL_SPLIT,
            leftComponent = self.request_pane.render(),
            rightComponent = JSplitPane(
                # Split within the right pane (top / bottom)
                JSplitPane.VERTICAL_SPLIT,
                leftComponent = self.history_log.render(),
                rightComponent = self.history_viewer.render()
            )
        )
        splitpane.setResizeWeight(0.4)
        top_panel.add(splitpane)
        return top_panel

    def send_to(self, url, request):
        """Handler to send attacker request through Burp context menu."""
        self.request_pane.send_to(url, request)
