import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import ActionListener
from javax.swing import JMenuItem


class ExecutorAction(ActionListener):
    """
    ExecutorAction class represent a context-free action class container.
    During creation an action should be passed to defined the behaviour of this context free action.
    """
    def __init__(self, text, action=None):
        self._action = action
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(True)
        self.menuitem.addActionListener(self)

    def actionPerformed(self, e):
        """
        Executes action if setup during creation.

        :param e: unused
        :return: None
        """
        if self._action:
            self._action(e)

    def ctx(self, host=None, payload=None, fname=None):
        """
        Do Nothing, stub implemented to be an action.
        This is not needed since the action to be performed is context free and setup during object creation.

        :param host: unused
        :param payload: unused
        :param fname: unused
        :return: None
        """
        pass