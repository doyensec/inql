# coding: utf-8
from burp import ITab

from java.awt import BorderLayout

from ..globals import montoya
from ..logger import log
from ..utils.ui import ui_panel
from .fileview import ScannerFileView
from .omnibar import ScannerOmnibar


class ScannerTab(ITab):
    """The main InQL tab called 'InQL Scanner'."""
    def getTabCaption(self):
        """Burp callback, should return title of the new tab."""
        return "InQL Scanner"

    def getUiComponent(self):
        """Burp callback, should return the Java UI component to be displayed in the tab."""
        log.debug("Collecting ScannerTab UI components...")
        ui = ui_panel(0)

        omnibar  = ScannerOmnibar()
        fileview = ScannerFileView()

        # Omnibar on top and the rest is Fileview
        ui.add(BorderLayout.PAGE_START, omnibar.render()) # self._omnibar.this
        ui.add(BorderLayout.CENTER, fileview.render())     # self._fileview.this

        montoya.userInterface().applyThemeToComponent(ui)

        log.debug("Finished collecting ScannerTab UI components!")
        return ui
