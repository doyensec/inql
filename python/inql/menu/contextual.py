# coding: utf-8
from burp import IContextMenuFactory

from java.awt.event import ActionListener
from javax.swing import JMenuItem

from ..globals import callbacks
from ..logger import log


class SendMenuItem(IContextMenuFactory):
    """Handles additional entries in context (right-click) menu in the "Send To ..." style."""
    def __init__(self, label, burp_handler):
        self.new_menu = JMenuItem("Send to %s" % label)
        self.label = label
        self.burp_handler = burp_handler
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        """Called on a right click, when context menu gets invoked."""
        listener = SendMenuListener(invocation, self.burp_handler)
        self.new_menu.addActionListener(listener)
        return [self.new_menu]


class SendMenuListenerFromScannerTab(ActionListener):
    def __init__(self, host, payload, inql_handler, burp_handler):
        self.inql_handler = inql_handler
        self.burp_handler = burp_handler
        self.host = host
        self.payload = payload

    def actionPerformed(self, _):
        log.debug("Click received! Host: %s, payload: %s" % (self.host, self.payload))
        self.inql_handler(self.host, self.payload, self.burp_handler)


class SendMenuListener(ActionListener):
    """Action Listener - listens for clicks inside the context menu."""
    def __init__(self, invocation, action):
        # Invocation contains information about where the context menu was invoked.
        self.invocation = invocation
        self.action = action

    def actionPerformed(self, _):
        """Called when a menu item gets clicked."""
        log.debug("Menu item click handler fired")
        for rr in self.invocation.getSelectedMessages():
            self.action(rr)
