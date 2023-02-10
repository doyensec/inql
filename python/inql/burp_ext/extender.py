import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import os
import shutil
import tempfile
import logging
import sys

#from burp import (IBurpExtender, IScannerInsertionPointProvider, IExtensionStateListener)
from burp import IExtensionStateListener

from inql import __version__
from inql.burp_ext.editor import GraphQLEditorTab
from inql.burp_ext.scanner import BurpScannerCheck
from inql.burp_ext.generator_tab import GeneratorTab
from inql.burp_ext.attacker_tab import AttackerTab
from inql.burp_ext.timer_tab import TimerTab
from inql.utils import stop

DEBUG = True

#class BurpExtender(IBurpExtender, IScannerInsertionPointProvider, IExtensionStateListener):
class BurpExtenderPython(IExtensionStateListener):
    """
    Main Class for Burp Extenders
    """

    def __init__(self, callbacks):
        self.callbacks = callbacks
        sys.stdout = self.callbacks.getStdout()
        sys.stderr = self.callbacks.getStderr()

        # adding the stdout and stderr to the burps one
        if DEBUG:
            logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.DEBUG)
        else:
            logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s')


        # setting the name of the extension
        self.callbacks.setExtensionName("InQL: Introspection GraphQL Scanner %s" % __version__)

        # shared data structured to store request issued across the extension
        self.requests = {}
        self.custom_headers = {}


    def registerExtenderCallbacks(self):
        """
        Overrides IBurpExtender method, it registers all the elements that compose this extension

        :return: None
        """

        # creating temp dir
        self._tmpdir = tempfile.mkdtemp()
        os.chdir(self._tmpdir)

        self.callbacks.issueAlert("InQL Scanner Started")
        
        helpers = self.callbacks.getHelpers()

        # Registering GraphQL Tab
        self.callbacks.registerMessageEditorTabFactory(lambda _, editable: GraphQLEditorTab(self.callbacks, editable))
        # Register ourselves as a custom scanner check
        self.callbacks.registerScannerCheck(BurpScannerCheck(self.callbacks))

        # Register Suite Tab(s)
        self._tab = GeneratorTab(self.callbacks, helpers, self.requests, self.custom_headers)
        self.callbacks.addSuiteTab(self._tab)
        self.callbacks.addSuiteTab(TimerTab(self.callbacks, helpers))
        self.callbacks.addSuiteTab(AttackerTab(self.callbacks, helpers))
        
        # Register extension state listener
        self.callbacks.registerExtensionStateListener(self)

        logging.info("InQL Scanner Started! (tmpdir: %s )" % os.getcwd())

    def extensionUnloaded(self):
        """
        Overrides IExtensionStateListener method, it unregisters all the element that compose this extension and it will save the
        state if available.

        :return: None
        """
        os.chdir('/')
        shutil.rmtree(self._tmpdir, ignore_errors=False, onerror=None)
        stop()
        self._tab.save()
        self._tab.stop()
