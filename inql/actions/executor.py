import platform

if platform.system() == "Java":
    from java.awt.event import ActionListener
    from javax.swing import JMenuItem

    class ExecutorAction(ActionListener):
        def __init__(self, text, action=None):
            self.text = text
            self.action = action
            self.menuitem = JMenuItem(text)
            self.menuitem.setEnabled(True)
            self.menuitem.addActionListener(self)

        def actionPerformed(self, e):
            if self.action:
                self.action(e)

        def ctx(self, host=None, payload=None, fname=None):
            pass