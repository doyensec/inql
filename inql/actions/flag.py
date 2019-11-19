import platform

if platform.system() == "Java":
    from java.awt.event import ActionListener
    from javax.swing import JMenuItem

    class FlagAction(ActionListener):
        def __init__(self, text_true="Flag Enabled", text_false="Flag Disabled", enabled=True):
            self.text_true = text_true
            self.text_false = text_false
            self.enabled = enabled
            self.menuitem = JMenuItem()
            self.menuitem.addActionListener(self)
            self.update()

        def update(self):
            if self.enabled:
                txt = self.text_true
            else:
                txt = self.text_false
            self.menuitem.setText(txt)

        def actionPerformed(self, e):
            self.enabled = not self.enabled
            self.update()

        def ctx(self, host=None, payload=None, fname=None):
            pass