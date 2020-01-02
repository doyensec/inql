from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from javax.swing import JFrame, JPanel, JLabel, JScrollPane, JTextArea
from javax.swing.event import DocumentListener
from java.awt import BorderLayout, Color


class _PayloadListener(DocumentListener):
    """
    PayloadListener wrapper is a java DocumentListener wrapper for python lambdas
    """
    def __init__(self, event_listener=lambda e: None, changed_update=None, remove_update=None, insert_update=None):
        self.changed_update = changed_update if changed_update else event_listener
        self.remove_update = changed_update if changed_update else event_listener
        self.insert_update = changed_update if changed_update else event_listener

    def removeUpdate(self, e):
        self.remove_update(e)

    def insertUpdate(self, e):
        self.insert_update(e)

    def changedUpdate(self, e):
        self.changed_update(e)


class PayloadView:
    """
    PayloadView is a TextView viewer and editor.
    """
    def __init__(self, payload=None, label=None):
        if not label: label = "PayloadView"

        self.this = JPanel()
        self.this.setLayout(BorderLayout())

        # Add a label
        self.this.add(BorderLayout.PAGE_START, JLabel(label))

        # Create textarea here and add to the JPanel
        scrollPane = JScrollPane()
        self._textarea = JTextArea()
        self._textarea.setColumns(20)
        self._textarea.setRows(5)
        self._textarea.setLineWrap(True)
        self._textarea.setWrapStyleWord(True)
        self._textarea.setEditable(True)
        self._textarea.setName("TextArea")
        self._textarea.setSelectionColor(Color(255, 153, 51))
        self._textarea.requestFocus()
        scrollPane.setViewportView(self._textarea)
        self.this.add(BorderLayout.CENTER, scrollPane)

        self.refresh(payload)

    def set_editable(self, editable):
        """
        Enable or Disable the editable textview

        :param editable: boolean parameter representing the editability
        :return: None
        """
        self._textarea.setEditable(editable)

    def refresh(self, payload):
        """
        Refresh the textarea content with a new payload, if present

        :param payload:
        :return: None
        """
        if payload:
            self._textarea.setText(payload)

    def add_listener(self, listener):
        """
        add a new listener to the textarea

        :param listener: this parameter should be a lambda or a method
        :return: None
        """
        self._textarea.getDocument().addDocumentListener(_PayloadListener(listener))

if __name__ == "__main__":
    frame = JFrame("PayloadView")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    ft = PayloadView(payload='Payload')
    ft.add_listener(lambda e: print(e))
    cp.add(ft.this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)