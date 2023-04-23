# coding: utf-8
import os
import shutil
import sys
import tempfile
import traceback

from burp import IExtensionStateListener, ITab

from com.formdev.flatlaf import FlatLightLaf
from javax.swing import JTabbedPane, UIManager

from gqlspection import log as gql_log

from .attacker.tab import AttackerTab
from .editors.payloadview import provideHttpRequestEditor
from .globals import app, callbacks, montoya
from .logger import log, set_log_level
from .menu.context_menu import ContextMenu
from .scanner.tab import ScannerTab
from .timer.tab import TimerTab
from .traffic_scan.scan_handler import BurpScannerCheck
from .utils.decorators import unroll_exceptions
from .utils.ui import ui_panel
from .scraper.headers_scraper import CustomProxyListener

DEBUG = True


class MainTab(ITab):
    """Main InQL interface - a Burp tab, that includes multiple subtabs."""
    pane = None
    panel = None
    tabs = None

    def __init__(self, *tabs):
        self.tabs = tabs

    def getTabCaption(self):
        return "InQL"

    def getUiComponent(self):
        self.panel = ui_panel()

        self.pane = JTabbedPane()
        for tab in self.tabs:
            self.pane.addTab(*tab)

        self.panel.add(self.pane)
        return self.panel


@unroll_exceptions
class BurpExtenderPython(IExtensionStateListener):
    """Class used to register extension in Burp Suite."""

    _scanner_tab  = None
    _timer_tab    = None
    _attacker_tab = None

    def __init__(self, burp_callbacks, upstream_montoya):
        callbacks.init(burp_callbacks)
        montoya.init(upstream_montoya)

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        if DEBUG:
            set_log_level(log, 'DEBUG')
            set_log_level(gql_log, 'DEBUG')
        else:
            set_log_level(log, 'INFO')
            set_log_level(gql_log, 'INFO')

        # creating temp dir
        self._tmpdir = tempfile.mkdtemp()
        os.chdir(self._tmpdir)

    def registerExtenderCallbacks(self):
        """Overrides IBurpExtender method, which registers all the elements that compose this extension."""

        callbacks.issueAlert("InQL Scanner Started")

        try:
            # Registering GraphQL editor tab
            montoya.userInterface().registerHttpRequestEditorProvider(provideHttpRequestEditor)
            # Register ourselves as a custom scanner check
            callbacks.registerScannerCheck(BurpScannerCheck())
            # Register the proxy listener 
            montoya.proxy().registerRequestHandler(CustomProxyListener(app.scraped_headers))


            app.burp_laf = UIManager.getLookAndFeel()
            app.flat_laf = FlatLightLaf()
            try:
                UIManager.setLookAndFeel(app.flat_laf)

                # Register Suite Tab(s)
                self._scanner_tab  = ScannerTab()
                self._timer_tab    = TimerTab()
                self._attacker_tab = AttackerTab()

                app.scanner_tab = self._scanner_tab.getUiComponent()
                app.timer_tab = self._timer_tab.getUiComponent()
                app.attacker_tab = self._attacker_tab.getUiComponent()

                app.main_tab = MainTab(
                    ("Scanner", app.scanner_tab),
                    ("Timer", app.timer_tab),
                    ("Attacker", app.attacker_tab)
                    # TODO add the settings here probably
                )
            except Exception as e:
                log.error("Exception: %s", str(e))
                log.debug("Exception: %s", str(e))
                raise
            finally:
                UIManager.setLookAndFeel(app.burp_laf)

            callbacks.addSuiteTab(app.main_tab)

            # Register extension state listener
            callbacks.registerExtensionStateListener(self)

            log.info("InQL Scanner Started! (tmpdir: %s )" % os.getcwd())
        except:
            log.info("oops, InQL crashed")
            traceback.print_exc(file=callbacks.getStderr())

        log.debug("Customizing context menu")
        montoya.userInterface().registerContextMenuItemsProvider(ContextMenu())

        log.debug("sys.path: {}".format(sys.path))
        log.debug("__file__: {}".format(__file__))

#        if DEBUG:
#            app.omnibar.url = 'https://google.com/graphql'
#            app.omnibar.file = ''
#            app.omnibar.run()


    def extensionUnloaded(self):
        """IExtensionStateListener method"""

        os.chdir(os.path.expanduser("~"))
        shutil.rmtree(self._tmpdir, ignore_errors=False, onerror=None)
