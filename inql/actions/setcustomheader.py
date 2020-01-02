from __future__ import print_function
import platform

from inql.utils import watch

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import ActionListener
from javax.swing import JMenuItem

from inql.widgets.propertyeditor import PropertyEditor


class CustomHeaderSetterAction(ActionListener):
    """
    Set Custom Header Action
    """

    def __init__(self, overrideheaders, text="Set Custom Header"):
        self.requests = {}
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)
        self.menuitem.addActionListener(self)
        self._overrideheaders = overrideheaders
        self._host = None

    def actionPerformed(self, e):
        """
        Overrides ActionListener behaviour, when clicked it opens the headers property editor for the given host.

        :param e: unused
        :return:
        """
        if self._host:
            try:
                self._overrideheaders[self._host]
            except KeyError:
                print("No custom header for %s, generating an empty set" % self._host)
                self._overrideheaders[self._host] = []
            PropertyEditor.get_instance("Set Custom Header for %s" % self._host,
                           columns=["Header", "Value"],
                           data=self._overrideheaders[self._host],
                           empty=["X-New-Header", "X-New-Header-Value"])

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