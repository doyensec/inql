import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import ActionListener
from javax.swing import JMenuItem


class FlagAction(ActionListener):
    """
    FlagAction represent a modifiable boolean setting associated with a menuitem.
    """
    def __init__(self, text_true="Flag Enabled", text_false="Flag Disabled", enabled=True):
        self._text_true = text_true
        self._text_false = text_false
        self._enabled = enabled
        self.menuitem = JMenuItem()
        self.menuitem.addActionListener(self)
        self._update()

    def enabled(self):
        """
        Returns true if enabled False otherwise

        :return: True if enabled, False otherwise
        """
        return self._enabled

    def _update(self):
        """
        Updates the tooltip state according to the enabled status.

        :return: None
        """
        if self._enabled:
            txt = self._text_true
        else:
            txt = self._text_false
        self.menuitem.setText(txt)

    def actionPerformed(self, e):
        """
        Overrides ActionListener behaviour. Toggle the enabled state.

        :param e: unused
        :return: None
        """
        self._enabled = not self._enabled
        self._update()

    def ctx(self, host=None, payload=None, fname=None):
        """
        Do nothing. The flag action is context free.

        :param host: unused
        :param payload: unused
        :param fname: unused
        :return: None
        """
        pass
