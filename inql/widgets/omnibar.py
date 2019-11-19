import platform

if platform.system() != "Java":
    print("Load this file inside Burp Suite/jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import FocusListener, KeyAdapter, KeyEvent
from javax.swing import JFrame, JPanel, JTextField, JButton
from java.awt import (BorderLayout, Color)

def nop(evt):
    pass

class HintTextField(FocusListener, KeyAdapter):
    def __init__(self, hint=None, action=None):
        if not hint: hint = 'hint'
        if not action: action = nop
        self.this = JTextField(hint)
        self.hint = hint
        self.showingHint = True
        self.enter_listener = None
        self.this.addFocusListener(self)
        self.this.addKeyListener(self)
        self.set_enter_evt_listener(action)

    def set_enter_evt_listener(self, enter_listener):
        self.enter_listener = enter_listener

    def keyPressed(self, e):
        if self.enter_listener and e.getKeyCode() == KeyEvent.VK_ENTER:
            self.enter_listener(e)
      
    def focusGained(self, e):
        if self.getText() == "":
            self.this.setText("")
            self.showingHint = False

    def focusLost(self, e):
        if self.getText() == "":
            self.this.setText(self.hint)
            self.showingHint = True

    def getText(self):
        if self.showingHint:
            return ""
        else:
            return self.this.getText()

class Omnibar:
    def __init__(self, hint=None, label=None, action=None):
        if not hint: hint = 'Omnibar hint'
        if not label: label = 'Run'
        if not action: action = nop
        self.this = JPanel()
        self.this.setLayout(BorderLayout())

        # Add an hinttextfield
        self.text = HintTextField(hint, action)
        self.this.add(BorderLayout.CENTER, self.text.this)

        # Add a run buttpn
        button = JButton(label)
        button.addActionListener(action)
        self.this.add(BorderLayout.EAST, button)

    def getText(self):
        return self.text.getText()

if __name__ == "__main__":
    frame = JFrame("Omnibar")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(Omnibar().this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)