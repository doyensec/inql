from javax.swing import JFrame, JTable, JScrollPane, JPopupMenu, JCheckBox
from java.awt import Color
from javax.swing.table import DefaultTableModel
from java.awt.event import WindowAdapter

from inql.actions.executor import ExecutorAction
from inql.utils import inherits_popup_menu

import logging

class HeadersSelector(WindowAdapter):
    """
    Selects which header to use in a new introspection request
    """

    def __init__(self, scraped_headers, custom_headers, text="Headers Selector"):
        """Created the component with all the possible headers to be added

        Args:
            scraped_headers (dict): dictionary of the scraped headers for a specific host
            custom_headers (dict): dictionary with the custom headers for a specific host
            text (str, optional): Title of the window. Defaults to "Headers Selector".
        """

        logging.debug("Inside the HeaderSelector class constructor")
        self.this = JFrame(text)
        self._text = text

        self._buttons = []

        # adding the buttons 
        for elem in scraped_headers:
            logging.debug("Element in screaped header is: %s: %s" % (elem, scraped_headers[elem]))
            self._buttons.append(JCheckBox(elem))
        
        # adding listeners to buttons 
        for button in self._buttons:
            button.addActionListener(self.this)

        # setting up the graphical part
        self.this.setForeground(Color.black)
        self.this.setBackground(Color.lightGray)
        self.this.pack()
        self.this.setVisible(True)
    
    def itemStateChange(self, evt):
        logging.debug("The state of an item is changed")
        logging.debug("The event is %s" % evt)

        # here I should add or remove the header form the custom headers
        # based on the user selection
    def actionPerformed(self, evt):
        logging.debug("The state of an item is changed")
        logging.debug("The event is %s" % evt)

        # here I should add or remove the header form the custom headers
        # based on the user selection