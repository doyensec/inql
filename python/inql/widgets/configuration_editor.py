import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import time
import logging

from java.awt import Color
from java.awt.event import WindowAdapter 
from javax.swing import JFrame, JTable, JScrollPane, JPopupMenu

from inql.actions.executor import ExecutorAction
from inql.utils import inherits_popup_menu
from javax.swing.table import DefaultTableModel


class ConfigurationEditor(WindowAdapter):
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
    def get_instance(
        text="Property Editor", 
        columns=None, 
        data=None,
        empty=None, 
        add_actions=True, 
        actions=None
        ):
        """
        Singleton Method based on the text property. It tries to generate only one property configuration page per text.

        :param text: getinstance key
        :param columns: proparty columns it should be an array alike
        :param data: it contains the current property rows
        :param empty: empty row property when adding a new one
        :param add_actions: include or not new actions
        :param actions: default set of actions to be appended to Add and Delete Rows
        :return: a new instance of ConfigurationEditor or a reused one.
        """        

        # Check if the instance is already present
        if text not in ConfigurationEditor.instances:
            logging.debug("Creating the Property editor")
            ConfigurationEditor.instances[text] = \
                ConfigurationEditor().__private_init__(text, columns, data, empty, add_actions, actions)

            # setting the location
            if text in ConfigurationEditor.locations:
                ConfigurationEditor.instances[text].this.setLocation(ConfigurationEditor.locations[text])
            elif ConfigurationEditor.last_location:
                ConfigurationEditor.instances[text].this.setLocation(
                    ConfigurationEditor.last_location.x+ConfigurationEditor.offset,
                    ConfigurationEditor.last_location.y+ConfigurationEditor.offset
                    )
                ConfigurationEditor.offset = ConfigurationEditor.NEW_WINDOW_OFFSET
            
            ConfigurationEditor.last_location = ConfigurationEditor.instances[text].this.getLocation()
            ConfigurationEditor.last_size = ConfigurationEditor.instances[text].this.getSize()

        # In any case I have to set it visible and on top
        ConfigurationEditor.instances[text].this.setVisible(True)
        ConfigurationEditor.instances[text].this.setAlwaysOnTop(True)
        ConfigurationEditor.instances[text].this.setAlwaysOnTop(False)
        
        return ConfigurationEditor.instances[text]

        
    def __private_init__(
        self, 
        text="Property Editor", 
        columns=None, 
        data=None, 
        empty=None, 
        add_actions=True, 
        actions=None
    ):
        """
        Args:
            text (str, optional): Identifier of the panel. Defaults to "Property Editor".
            columns (_type_, optional): List of columns. Defaults to None.
            data (_type_, optional): Data to be displayed. Defaults to None.
            empty (_type_, optional): Content of a new row before modications. Defaults to None.
            add_actions (bool, optional): Defaults to True.
            actions (_type_, optional): List of actions. Defaults to None.
        """
        if not actions: actions = []
        if not columns: columns = []
        if not data: data = []
        if not empty: empty = []

        logging.debug("Type of data = %s" % type(data))
        
        self._text = text
        self.this = JFrame(text)
        self._table = JTable()
        self._dtm = DefaultTableModel(0, 0)
        self._dtm.setColumnIdentifiers(columns)
        self._table.setModel(self._dtm)
        self._data = data

        for d in data.keys():
            new_row = [d, data[d]]
            logging.debug("New row: %s" % new_row)
            self._dtm.addRow(new_row)
            
        self._pane = JScrollPane(self._table)
        self.this.add(self._pane)
        self._empty = empty

        self.this.addWindowListener(self)

        self._dtm.addTableModelListener(lambda _: self._update_model())
        self.this.setLocation(ConfigurationEditor.NEW_WINDOW_OFFSET, ConfigurationEditor.NEW_WINDOW_OFFSET)

        if add_actions:
            self._popup = JPopupMenu()
            self._pane.setComponentPopupMenu(self._popup)
            inherits_popup_menu(self._pane)

            self._actions = actions
            self._actions.append(ExecutorAction('Remove Selected Rows', action=lambda e: self._remove_row()))
            self._actions.append(ExecutorAction('Add New Row', action=lambda e: self._add_row()))

            for action in self._actions:
                self._popup.add(action.menuitem)

        self.this.setForeground(Color.black)
        self.this.setBackground(Color.lightGray)
        self.this.pack()
        self.this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)

        return self

    def _add_row(self):
        """
        Add a new row the selection

        :return: None
        """
        self._dtm.addRow(self._empty)

    def _remove_row(self):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._table.getSelectedRows()
        logging.debug("The rows to be removed are: ")
        logging.debug(rows)
        for i in range(0, len(rows)):
            # TODO remove from data
            self._data.pop()
            self._dtm.removeRow(rows[i] - i)


    def windowClosing(self, evt):
        """
        Overrides WindowAdapter method

        :param evt: unused
        :return: None
        """
        ConfigurationEditor.locations[self._text] = self.this.getLocation()
        ConfigurationEditor.sizes[self._text] = self.this.getSize()
        ConfigurationEditor.last_location = self.this.getLocation()
        ConfigurationEditor.last_size = self.this.getSize()
        ConfigurationEditor.offset = 0
        self.this.setVisible(False)

    def _update_model(self):
        """
        Update the data content with the updated rows

        :return: None
        """        
        
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
                        
            # Updating the row
            self._data[new_row[0]] = new_row[1]
            
                

if __name__ == "__main__":
    data = [['a', 'b'], ['c', 'd']]
    pe = HeadersEditor.get_instance(columns=['flag', 'ciao', 'bao'], data=data, empty=[False, 'e1', 'e2'])
    while True:
        time.sleep(10)
        pe = HeadersEditor.get_instance(columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
        HeadersEditor.get_instance(text='test2', columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
        print(pe._data)
