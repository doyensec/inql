import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import time

from javax.swing import JFrame, JTable, JScrollPane, JPopupMenu
from java.awt import Color
from javax.swing.table import DefaultTableModel
from java.awt.event import WindowAdapter

from inql.actions.executor import ExecutorAction
from inql.utils import inherits_popup_menu

class PropertyEditor(WindowAdapter):
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
    def get_instance(text="Property Editor", columns=None, data=None, empty=None, add_actions=True, actions=None):
        """
        Singleton Method based on the text property. It tries to generate only one property configuration page per text.

        :param text: getinstance key
        :param columns: proparty columns it should be an array alike
        :param data: it contains the current property rows
        :param empty: empty row property when adding a new one
        :param add_actions: include or not new actions
        :param actions: default set of actions to be appended to Add and Delete Rows
        :return: a new instance of PropertyEditor or a reused one.
        """
        if not actions: actions = []
        if not columns: columns = []
        if data == None: data = []
        if not empty: empty = []
        try:
            PropertyEditor.instances[text]
        except KeyError:
            PropertyEditor.instances[text] = \
                PropertyEditor().__private_init__(text, columns, data, empty, add_actions, actions)
            try:
                PropertyEditor.instances[text].this.setLocation(PropertyEditor.locations[text])
            except KeyError:
                if PropertyEditor.last_location:
                    PropertyEditor.instances[text].this.setLocation(
                        PropertyEditor.last_location.x+PropertyEditor.offset,
                        PropertyEditor.last_location.y+PropertyEditor.offset)
                    PropertyEditor.offset = PropertyEditor.NEW_WINDOW_OFFSET
            try:
                PropertyEditor.instances[text].this.setSize(PropertyEditor.sizes[text])
            except KeyError:
                if PropertyEditor.last_size:
                    PropertyEditor.instances[text].this.setSize(PropertyEditor.last_size)
            PropertyEditor.last_location = PropertyEditor.instances[text].this.getLocation()
            PropertyEditor.last_size = PropertyEditor.instances[text].this.getSize()
        ## Hack ON: Bring on Front
        PropertyEditor.instances[text].this.setAlwaysOnTop(True)
        PropertyEditor.instances[text].this.setAlwaysOnTop(False)
        ## Hack OFF
        return PropertyEditor.instances[text]

    def __private_init__(self, text="Property Editor", columns=None, data=None, empty=None, add_actions=True, actions=None):
        if not actions: actions = []
        if not columns: columns = []
        if data == None: data = []
        if not empty: empty = []

        self._text = text
        self.this = JFrame(text)
        self._table = JTable()
        self._dtm = DefaultTableModel(0, 0)
        self._dtm.setColumnIdentifiers(columns)
        self._table.setModel(self._dtm)
        self._data = data
        for d in data:
            self._dtm.addRow(d)
        self._pane = JScrollPane(self._table)
        self.this.add(self._pane)
        self._empty = empty

        self.this.addWindowListener(self)

        self._dtm.addTableModelListener(lambda _: self._update_model())
        self.this.setLocation(PropertyEditor.NEW_WINDOW_OFFSET, PropertyEditor.NEW_WINDOW_OFFSET)

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
        self.this.setVisible(True)
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
        for i in range(0, len(rows)):
            self._dtm.removeRow(rows[i] - i)

    def windowClosing(self, evt):
        """
        Overrides WindowAdapter method

        :param evt: unused
        :return: None
        """
        PropertyEditor.locations[self._text] = self.this.getLocation()
        PropertyEditor.sizes[self._text] = self.this.getSize()
        PropertyEditor.last_location = self.this.getLocation()
        PropertyEditor.last_size = self.this.getSize()
        PropertyEditor.offset = 0
        self.this.setVisible(False)
        self.this.dispose()
        del PropertyEditor.instances[self._text]

    def _update_model(self):
        """
        Update the data content with the updated rows

        :return: None
        """
        del self._data[:]
        nRow = self._dtm.getRowCount()
        nCol = self._dtm.getColumnCount()
        for i in range(0, nRow):
            self._data.append([None] * nCol)
            for j in range(0, nCol):
                d = str(self._dtm.getValueAt(i, j)).lower()
                if d == 'none' or d == '':
                    self._data[i][j] = None
                elif d == 'true' or d == 't':
                    self._data[i][j] = True
                elif d == 'false' or d == 'f':
                    self._data[i][j] = False
                else:
                    try:
                        self._data[i][j] = int(self._dtm.getValueAt(i, j))
                    except ValueError:
                        self._data[i][j] = self._dtm.getValueAt(i, j)

if __name__ == "__main__":
    data = [['a', 'b'], ['c', 'd']]
    pe = PropertyEditor.get_instance(columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
    while True:
        time.sleep(10)
        pe = PropertyEditor.get_instance(columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
        PropertyEditor.get_instance(text='test2', columns=['ciao', 'bao'], data=data, empty=['e1', 'e2'])
        print(pe._data)
