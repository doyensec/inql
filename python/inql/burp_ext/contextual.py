import logging
from java.awt.event import ActionListener
from javax.swing import JMenuItem

from burp import IContextMenuFactory

from inql.utils import is_query

class SendMenuItem(IContextMenuFactory):
    """Handles additional entries in context (right-click) menu in the "Send To ..." style.
    
    This is a new approach, that's only used for "Send to Attacker" right now.
    The older class, OmniMenuItem has reached it's extensibility.
    """
    def __init__(self, callbacks, label, inql_handler=None, burp_handler=None):
        # legacy menu, used in InQL Scanner tab
        self.menuitem = JMenuItem("Send to %s" % label)
        self.new_menu = JMenuItem("Send to %s" % label)
        self.label = label
        self.burp_handler = burp_handler
        self.inql_handler = inql_handler
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        """Overrides IContextMenuFactory callback
        
        Called on a right click, when context menu gets invoked.
        """
        if self.burp_handler is None:
            return

        listener = SendMenuListener(invocation, self.burp_handler)
        self.new_menu.addActionListener(listener)
        return [self.new_menu]

    def ctx(self, host=None, payload=None, fname=None):
        """Called every time a query gets selected in "InQL Scanner" tab.
        
        The createMenuItem does not get called and self.menuitem is accessed manually,
        thus listener needs to be set up manually (and it receives different input).
        """
        # Remove previous listeners, if any are set.
        for listener in self.menuitem.getActionListeners():
            self.menuitem.removeActionListener(listener)

        # Set up a new listener, passing it selected GraphQL payload.
        listener = SendMenuListenerFromScannerTab(host, payload, self.inql_handler, self.burp_handler)
        self.menuitem.addActionListener(listener)

class SendMenuListenerFromScannerTab(ActionListener):
    def __init__(self, host, payload, inql_handler, burp_handler):
        self.inql_handler = inql_handler
        self.burp_handler = burp_handler
        self.host = host
        self.payload = payload

    def actionPerformed(self, event):
        logging.debug("Click received! Host: %s, payload: %s" % (self.host, self.payload))
        self.inql_handler(self.host, self.payload, self.burp_handler)

class SendMenuListener(ActionListener):
    """Action Listener - listens for clicks inside the context menu."""
    def __init__(self, invocation, action):
        # Invocation contains information about where the context menu was invoked.
        self.invocation = invocation
        self.action = action

    def actionPerformed(self, event):
        """Called when a menu item gets clicked."""
        for rr in self.invocation.getSelectedMessages():
            self.action(rr)

class OmniMenuItem(IContextMenuFactory):
    """Menu item for burp and inql interface. IT contains same action but it is shown in multiple places"""
    def __init__(self, helpers=None, callbacks=None, text=''):
        self._helpers = helpers
        self._callbacks = callbacks
        self.menuitem = JMenuItem(text)
        self._burp_menuitem = JMenuItem("inql: %s" % text)
        self.set_enabled(False)
        self._callbacks.registerContextMenuFactory(self)

    def add_action_listener(self, action_listener):
        """
        add a new action listener to the given UI items.
        """
        self._action_listener = action_listener
        self.menuitem.addActionListener(action_listener)
        self._burp_menuitem.addActionListener(action_listener)

    def set_enabled(self, enabled):
        """
        Enables or disables the menuitme
        """
        self.menuitem.setEnabled(enabled)
        self._burp_menuitem.setEnabled(enabled)

    def createMenuItems(self, invocation):
        """
        Overrides IContextMenuFactory callback

        :param invocation: handles menu selected invocation
        :return:
        """
        try:
            r = invocation.getSelectedMessages()[0]
            info = self._helpers.analyzeRequest(r)
            url = str(info.getUrl())
            body = r.getRequest()[info.getBodyOffset():].tostring()
            if not is_query(body):
                return None
            for h in info.getHeaders():
                if h.lower().startswith("host:"):
                    domain = h[5:].strip()

            self._action_listener.ctx(fname='dummy.query', host=domain, payload=body)
            mymenu = []
            mymenu.append(self._burp_menuitem)
        except Exception as ex:
            return None
        return mymenu
