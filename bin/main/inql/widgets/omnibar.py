import platform
import logging

from inql.utils import nop_evt

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from java.awt.event import FocusListener, KeyAdapter, KeyEvent
from javax.swing import JFrame, JPanel, JTextField, JButton
from java.awt import (BorderLayout, Color, Dimension, GridBagConstraints, GridBagLayout)


class _HintTextField(FocusListener, KeyAdapter):
    """
    HintTextField is a class responsible for showing an hint while the textfield is empty
    """

    def __init__(self, hint=None, action=None):
        if not hint: hint = 'hint'
        if not action: action = nop_evt
        self.this = JTextField(hint)
        # self.this.setMaxSize(Dimension( 2000, 24 ))
        # self.this.setMinSize(Dimension( 200, 24 ))

        self._hint = hint
        self._showing_hint = True
        self._enter_listener = None
        self.this.addFocusListener(self)
        self.this.addKeyListener(self)
        self.set_enter_evt_listener(action)

    def set_enter_evt_listener(self, enter_listener):
        """
        Add an evt listener to HintTextField

        :param enter_listener: lambda event listener
        :return:
        """
        self._enter_listener = enter_listener

    def keyPressed(self, e):
        """
        KeyAdapter override

        :param e: event containing the key pressed
        :return: None
        """
        if self._enter_listener and e.getKeyCode() == KeyEvent.VK_ENTER:
            self._enter_listener(e)
      
    def focusGained(self, e):
        """
        FocusListener override

        :param e: unused
        :return: None
        """
        if self.getText() == "":
            self.this.setText("")
            self._showing_hint = False

    def focusLost(self, e):
        """
        FocusListener override

        :param e: unused
        :return: None
        """
        if self.getText() == "":
            self.this.setText(self._hint)
            self._showing_hint = True

    def getText(self):
        """
        :return: the current text or "" if no text is wrote inside the textfield
        """
        if self._showing_hint:
            return ""
        else:
            return self.this.getText()

    def setText(self, txt):
        """
        Set Text

        :param txt: a string
        :return: None
        """
        self.this.setText(txt)
        self._showing_hint = False

    def reset(self):
        """
        Reset the HintBox
        :return: None
        """
        self.this.setText(self._hint)
        self._showing_hint = True

class Omnibar:
    """
    Omnibar represents a chrome alike textbox with behaviour similar to the one of a normal browser
    """

    def __init__(self, hint=None, label=None, action=None):
        if not hint: hint = 'Omnibar hint'
        if not label: label = 'Run'
        if not action: action = nop_evt
        self.this = JPanel()
        self.this.setLayout(BorderLayout())

        # Add an hinttextfield
        self._text = _HintTextField(hint, action)
        self.this.add(BorderLayout.CENTER, self._text.this)

        # Add a run buttpn
        button = JButton(label)
        button.addActionListener(action)
        self.this.add(BorderLayout.EAST, button)

    def getText(self):
        """
        :return: the current text or "" if no text is wrote inside the textfield
        """
        return self._text.getText()

    def setText(self, txt):
        """
        Set Text

        :param txt: a string
        :return: None
        """
        self._text.setText(txt)

    def reset(self):
        """
        Reset the HintBox
        :return: None
        """
        self._text.reset()

class OmnibarMultipleActions:
    """
    Omnibar represents a chrome alike textbox with behaviour similar to the one 
    of a normal browser
    
    Multiple actions is intended to be used when multiple buttons should be 
    displayed in the same omnibar. The hint is only given for the first action
    """

    def __init__(self, hint=None, labels=None, actions=None):
        if not hint: hint = 'Omnibar hint'
        if not actions: actions = [nop_evt]
        if not labels: labels = ['Run']*len(actions)
        
        self.this = JPanel()
        self.this.setLayout(GridBagLayout())

        grid = GridBagConstraints()
        grid.fill = GridBagConstraints.HORIZONTAL        

        # Add an hinttextfield
        self._text = _HintTextField(hint, actions[0])
        grid.weightx = 7
        grid.gridx = 0
        self.this.add(self._text.this, grid)

        grid_pos = 8

        for action, label in zip(actions, labels):
            # Add a run buttpn
            logging.debug("Adding label %s to action %s", label, action)
            button = JButton(label)
            button.addActionListener(action)
            grid.weightx = 0.3
            grid.gridx = grid_pos
            grid_pos += 1 
            self.this.add(button, grid)

    def getText(self):
        """
        :return: the current text or "" if no text is wrote inside the textfield
        """
        return self._text.getText()

    def setText(self, txt):
        """
        Set Text

        :param txt: a string
        :return: None
        """
        self._text.setText(txt)

    def reset(self):
        """
        Reset the HintBox
        :return: None
        """
        self._text.reset()

if __name__ == "__main__":
    frame = JFrame("Omnibar")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(Omnibar().this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)