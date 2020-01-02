import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from inql.widgets.propertyeditor import PropertyEditor
from java.awt.event import ActionListener
from javax.swing import JMenuItem


class CustomHeaderSetter(ActionListener):
    def __init__(self, overrideheaders, text="Set Custom Header"):
        self.requests = {}
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(False)
        self.overrideheaders = overrideheaders

    def actionPerformed(self, e):
        if self.host:
            try:
                self.overrideheaders[self.host]
            except KeyError:
                self.overrideheaders[self.host] = {}

            PropertyEditor("Set Custom Header for %s" % self.host,
                           columns=["Header", "Value"],
                           data=self.overrideheaders[self.host],
                           empty=["X-New-Header", "X-New-Header-Value"]).show_option_dialog()

    def ctx(self, host=None, payload=None, fname=None):
        if host:
            self.menuitem.setEnabled(True)
        self.host = host