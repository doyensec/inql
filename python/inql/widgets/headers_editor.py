import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import time
import logging

from java.awt import Color
from java.awt.event import WindowAdapter 
from java.awt import BorderLayout
from javax.swing import JFrame, JTable, JScrollPane, JPopupMenu, JTabbedPane, JLabel, JButton, JPanel
from javax.swing.table import DefaultTableModel

from java.lang import Boolean

from inql.actions.executor import ExecutorAction
from inql.utils import inherits_popup_menu
from inql.widgets.custom_table import CustomTable


class CustomTable(DefaultTableModel):
    """
    Custom Table Model implementation. It is required to override the getColumnClass method
    and enable the correct rendered for the Boolean Type (which will be redered as a checkbox)
    """
    def getColumnClass(self, c):
        t = self.getValueAt(0, c)
        if type(t) != bool:
            return type(t)

        # In case the type is bool, I need to return the real Boolean type of Java
        x = Boolean(False)
        return type(x)

class HeadersEditor(WindowAdapter):
    """
    Edits Tabular Properties of a given WindowAdapter
    """
    instances = {}
    last_location = None
    locations = {}
    last_size = None
    sizes = {}

    NEW_WINDOW_OFFSET = 32
    offset = NEW_WINDOW_OFFSET

    @staticmethod
    def get_instance(custom_headers, scraped_headers, text="Header Selector"):
        """
        Singleton Method based on the text property. It tries to generate only one header selector configuration page per text.

        :param custom_headers: it contains the current custom headers
        :param scraped_headers: it contains the current scraped headers 
        :param text: getinstance key
        :return: a new instance of HeadersEditor or a reused one.
        """        

        # Check if the instance is already present
        if text not in HeadersEditor.instances:
            logging.debug("Creating the Property editor")
            HeadersEditor.instances[text] = \
                HeadersEditor().__private_init__(text, custom_headers, scraped_headers)

            # setting the location
            if text in HeadersEditor.locations:
                HeadersEditor.instances[text].this.setLocation(HeadersEditor.locations[text])
            elif HeadersEditor.last_location:
                HeadersEditor.instances[text].this.setLocation(
                    HeadersEditor.last_location.x+HeadersEditor.offset,
                    HeadersEditor.last_location.y+HeadersEditor.offset
                    )
                HeadersEditor.offset = HeadersEditor.NEW_WINDOW_OFFSET
            
            HeadersEditor.last_location = HeadersEditor.instances[text].this.getLocation()
            HeadersEditor.last_size = HeadersEditor.instances[text].this.getSize()

        # In any case I have to set it visible and on top
        HeadersEditor.instances[text].this.setVisible(True)
        HeadersEditor.instances[text].this.setAlwaysOnTop(True)
        HeadersEditor.instances[text].this.setAlwaysOnTop(False)
        
        return HeadersEditor.instances[text]

    def __private_init__(self, text, custom_headers, scraped_headers):
        """Build the GUI for the header selection associate to a particular "text" 
        which is usually associated to a HOST

        Args:
            text (str): Is the title of the panel
            custom_headers (list): Custom headers defined by the user for that particular host
            scraped_headers (dict): Scraped headers for that particular host

        Returns:
            _type_: _description_
        """

        self._empty = [False, "X-New-Header", "X-New-Header-Value"]
        self._text = text
        self._custom_headers = custom_headers
        self._scraped_headers = scraped_headers

        # Data to store the state of the custom and scraped headers. 
        # Inside the private data will be stored all the headers while in the
        # Data structures we will only store the selected ones (for the custom)
        self._custom_private_data = {}
        
        # Rows to be moved once the "Move button" is pressed
        self._scraped_private_data = {} 

        # Table to display the headers 
        self._build_custom_headers_table()
        self._build_scraped_headers_table()
        self._build_gui_tabs()

        # Augmenting custom headers with object boolean 
        self._augmenting_custom_headers_data()
        self._augmenting_scraped_headers_data()

        # Setup actions. Custom header can be added and removed, scraped one can only be removed
        self._add_custom_headers_actions()
        self._add_scraped_headers_actions()

        return self

    def _build_custom_headers_table(self):        
        custom_headers_columns = ["Flag", "Header", "Value"]
        self._custom_headers_table = JTable()
        self._custom_headers_dtm = CustomTable(0, 0)
        self._custom_headers_dtm.setColumnIdentifiers(custom_headers_columns)
        self._custom_headers_table.setModel(self._custom_headers_dtm)

        self._custom_headers_dtm.addTableModelListener(lambda _: self._custom_headers_update())


    def _build_scraped_headers_table(self):
        scraped_headers_columns = ["Header", "Value"]
        self._scraped_headers_table = JTable()
        self._scraped_headers_dtm = CustomTable(0, 0)
        self._scraped_headers_dtm.setColumnIdentifiers(scraped_headers_columns)
        self._scraped_headers_table.setModel(self._scraped_headers_dtm)

    def _build_gui_tabs(self):

        self.this = JFrame(self._text)
        self._main_panel = JTabbedPane()

        self._custom_headers_label = JLabel("Custom Headers")
        self._custom_headers_label.setHorizontalAlignment(JLabel.CENTER)
        self._custom_headers_pane = JScrollPane(self._custom_headers_table)
        self._custom_headers_pane.add(self._custom_headers_label)

        self._scrpaded_heders_main_pane = JPanel(BorderLayout())

        self._scraped_headers_label = JLabel("Scraped Headers")
        self._scraped_headers_label.setHorizontalAlignment(JLabel.CENTER)
        self._scraped_headers_pane = JScrollPane(self._scraped_headers_table)
        self._scraped_headers_pane.add(self._scraped_headers_label)

        self._button_pane = JPanel()
        self._move_button = JButton("Move to Custom")
        self._move_button.addActionListener(lambda _: self._move_scraped_headers_row())
        self._button_pane.add(self._move_button)

        self._scrpaded_heders_main_pane.add(self._scraped_headers_pane, BorderLayout.CENTER)
        self._scrpaded_heders_main_pane.add(self._button_pane, BorderLayout.PAGE_END)

        self._main_panel.addTab("Custom Headers", self._custom_headers_pane)
        self._main_panel.addTab("Scraped Headers", self._scrpaded_heders_main_pane)
        self._main_panel.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

        self.this.add(self._main_panel)
        self.this.addWindowListener(self)

        self.this.setLocation(HeadersEditor.NEW_WINDOW_OFFSET, HeadersEditor.NEW_WINDOW_OFFSET)

        # Conclude the GUI setup
        self.this.setForeground(Color.black)
        self.this.setBackground(Color.lightGray)
        self.this.pack()
        self.this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)

    def _augmenting_custom_headers_data(self):
        for k, v in self._custom_headers:
            # Building the idx for the private data 
            row = "%s:%s" % (k, v)

            # Check if I have a preference in memory
            if row in self._custom_private_data:
                new_row = [self._custom_private_data[row], k, v]
            else:
                # By default select it if is custom
                self._custom_private_data[row] = True
                new_row = [True, k, v]
            
            logging.debug("New row: %s" % new_row)
            self._custom_headers_dtm.addRow(new_row)

        self._custom_headers_dtm.addRow(self._empty)
        self._custom_headers_dtm.addRow(self._empty)
        self._custom_headers_dtm.addRow(self._empty)
    
    def _augmenting_scraped_headers_data(self):
        for k in self._scraped_headers.keys():
            new_row = [k, self._scraped_headers[k]]
            self._scraped_headers_dtm.addRow(new_row)

    def _add_custom_headers_actions(self):
        self._custom_header_popup = JPopupMenu()
        self._custom_headers_pane.setComponentPopupMenu(self._custom_header_popup)
        inherits_popup_menu(self._custom_headers_pane)

        self._custom_header_actions = []
        self._custom_header_actions.append(ExecutorAction('Remove Selected Rows', action=lambda e: self._remove_custom_headers_row()))
        self._custom_header_actions.append(ExecutorAction('Add New Row', action=lambda e: self._add_custom_headers_row()))
        for action in self._custom_header_actions:
                self._custom_header_popup.add(action.menuitem)
    
    def _add_scraped_headers_actions(self):
        self._scraped_header_popup = JPopupMenu()
        self._scraped_headers_pane.setComponentPopupMenu(self._scraped_header_popup)
        inherits_popup_menu(self._scraped_headers_pane)

        self._scraped_header_actions = []
        self._scraped_header_actions.append(ExecutorAction('Move to Custom Headers', action=lambda e: self._move_scraped_headers_row()))
        self._scraped_header_actions.append(ExecutorAction('Remove Selected Rows', action=lambda e: self._remove_scraped_headers_row()))
        for action in self._scraped_header_actions:
                self._scraped_header_popup.add(action.menuitem)

    def _add_custom_headers_row(self):
        """
        Add a new row the selection

        :return: None
        """
        self._custom_headers_dtm.addRow(self._empty)

    def _remove_custom_headers_row(self):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._custom_headers_table.getSelectedRows()
        for i in range(0, len(rows)):
            self._custom_headers_dtm.removeRow(rows[i] - i)
    
    def _remove_scraped_headers_row(self):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._scraped_headers_table.getSelectedRows()
        for i in range(0, len(rows)):
            self._scraped_headers_dtm.removeRow(rows[i] - i)

    
    def _move_scraped_headers_row(self):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._scraped_headers_table.getSelectedRows()
        logging.debug("The selected rows are:")
        logging.debug(rows)

        cols = self._scraped_headers_table.getColumnCount()

        for i in range(0, len(rows)):
            row_to_move = [False]
            for j in range(cols):
                row_to_move.append(self._scraped_headers_dtm.getValueAt(rows[i] - i, j))
            
            logging.debug("Adding new row: %s" % row_to_move)
            self._custom_headers_dtm.addRow(row_to_move)
            self._scraped_headers_dtm.removeRow(rows[i] - i)


    def windowClosing(self, evt):
        """
        Overrides WindowAdapter method

        :param evt: unused
        :return: None
        """
        HeadersEditor.locations[self._text] = self.this.getLocation()
        HeadersEditor.sizes[self._text] = self.this.getSize()
        HeadersEditor.last_location = self.this.getLocation()
        HeadersEditor.last_size = self.this.getSize()
        HeadersEditor.offset = 0
        self.this.setVisible(False)

    def _custom_headers_update(self):
        """
        Update the data content with the updated rows

        The old state, stored in self._private_data, is updated. 
        Depending on the presence or not of the dest_data structure, 
        the updates are stored either there or in the self._src_data

        :return: None
        """

        del self._custom_headers[:]
        
        nRow = self._custom_headers_dtm.getRowCount()
        nCol = self._custom_headers_dtm.getColumnCount()
        for i in range(0, nRow):
            # Creating the new row
            new_row = [None] * nCol
            for j in range(0, nCol):
                d = str(self._custom_headers_dtm.getValueAt(i, j)).lower()
                if d == 'none' or d == '':
                    new_row[j] = None
                elif d == 'true' or d == 't':
                    new_row[j] = True
                elif d == 'false' or d == 'f':
                    new_row[j] = False
                else:
                    try:
                        new_row[j] = int(self._custom_headers_dtm.getValueAt(i, j))
                    except ValueError:
                        new_row[j] = self._custom_headers_dtm.getValueAt(i, j)
            
            idx = "%s:%s" % (new_row[1], new_row[2])
            logging.debug("The idx is: %s" % idx)
            self._custom_private_data[idx] = new_row[0]
            logging.debug("self._private_data[%s] = %s" % (new_row[1:], new_row[0]))
            
            # Adding the new row to the private headers to be displayed
            if new_row[0] == True:
                self._custom_headers.append(new_row[1:])
    
    def _scraped_headers_update(self):
        """
        Update the data content with the updated rows

        The old state, stored in self._private_data, is updated. 
        Depending on the presence or not of the dest_data structure, 
        the updates are stored either there or in the self._src_data

        :return: None
        """
        # logging.debug("Updating the model")
        # if self._dest_data:
        #     del self._dest_data[:]
        # else:
        #     del self._src_data[:]
        
        
        nRow = self._dtm.getRowCount()
        nCol = self._dtm.getColumnCount()
        for i in range(0, nRow):
            # Creating the new row
            new_row = [None] * nCol
            for j in range(0, nCol):
                d = str(self._dtm.getValueAt(i, j)).lower()
                if d == 'none' or d == '':
                    new_row[j] = None
                elif d == 'true' or d == 't':
                    new_row[j] = True
                elif d == 'false' or d == 'f':
                    new_row[j] = False
                else:
                    try:
                        new_row[j] = int(self._dtm.getValueAt(i, j))
                    except ValueError:
                        new_row[j] = self._dtm.getValueAt(i, j)
            
            idx = "%s:%s" % (new_row[1], new_row[2])
            logging.debug("The idx is: %s" % idx)
            self._private_data[idx] = new_row[0]
            logging.debug("self._private_data[%s] = %s" % (new_row[1:], new_row[0]))
            
            # Adding the new row to the private headers to be displayed
            if new_row[0] == True:
                if self._dest_data:
                    self._dest_data[new_row[1]] = new_row[2]
                else:
                    self._src_data[new_row[1]] = new_row[2]
            else:
                # remove from data in case dest_data is false
                if self._dest_data == None:
                    self._src_data.pop(new_row[1])
                

if __name__ == "__main__":
    data = [['a', 'b'], ['c', 'd']]
    pe = HeadersEditor.get_instance(columns=['flag', 'ciao', 'bao'], data=data, empty=[False, 'e1', 'e2'])
    while True:
        time.sleep(10)
        pe = HeadersEditor.get_instance(columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
        HeadersEditor.get_instance(text='test2', columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
        print(pe._data)
