from __future__ import print_function
import platform
import logging

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import ActionListener
from javax.swing import JMenuItem, JCheckBox

from inql.widgets.headers_editor import HeadersEditor


class CustomHeaderSetterAction(ActionListener):
    """
    Set Custom Header Action
    """

    def __init__(self, custom_headers, scraped_headers, text="Set Custom Header"):
        self.requests = {}
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)
        self.menuitem.addActionListener(self)
        self._custom_headers = custom_headers
        self._scraped_headers = scraped_headers
        self._host = None

    def actionPerformed(self, e):
        """
        Overrides ActionListener behaviour, when clicked it opens the headers property editor for the given host.

        :param e: unused
        :return:
        """
        if self._host:
            # Check if host is present in custom headers and scraped headers
            if not self._host in self._custom_headers:
                logging.debug("No custom header for %s, generating an empty set" % self._host)
                self._custom_headers[self._host] = []
            if not self._host in self._scraped_headers:
                logging.debug("No scraped header for %s, generating an empty set" % self._host)
                self._scraped_headers[self._host] = {}
            
            HeadersEditor.get_instance(
                           custom_headers=self._custom_headers[self._host],
                           scraped_headers=self._scraped_headers[self._host],
                           text="Set Custom Header for %s" % self._host)

    def ctx(self, host=None, payload=None, fname=None):
        """
        implements the context setting behaviour

        :param host: when host is not null set it and enable the menuitem.
        :param payload: ignored
        :param fname: ignored
        :return:
        """
        if host:
            self.menuitem.setEnabled(True)
        else:
            self.menuitem.setEnabled(False)
        self._host = host
