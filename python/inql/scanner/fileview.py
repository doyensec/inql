# coding: utf-8
from javax.swing import JSplitPane

from ..globals import app
from ..logger import log
from .filetree import ScannerFileTree
from .payloadview import ScannerPayloadView


class ScannerFileView(object):
    """The component that displays introspection analysis results."""
    def __init__(self):
        # There is a clickable file tree on the left and an editor with a single query on the right
        log.debug("ScannerFileView initiated")
        self.payloadview = ScannerPayloadView()
        log.debug("After payloadview")
        self.filetree = ScannerFileTree(self)
        log.debug("After ScannerFileTree")

        self.component = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                               self.filetree.render(),
                               self.payloadview.render())

        self.component.setOneTouchExpandable(True)
        self.component.getRightComponent().setVisible(True)
        self.component.setDividerLocation(0.5)
        self.component.setResizeWeight(0.40)


        # Add global pointer to this object as we'll need to refresh it upon changes
        app.fileview = self

    def render(self):
        log.debug("ScannerFileView.render()")
        return self.component

    def refresh(self):
        """Refresh after external changes (likely new results incoming)"""
        self.filetree.refresh()
