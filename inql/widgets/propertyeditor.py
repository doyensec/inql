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
    def __init__(self, text="Property Editor", columns=[], data=[], empty=[]):
        self.this = JFrame(text)
        self._table = JTable()
        self._dtm = DefaultTableModel(0, 0)
        self._dtm.setColumnIdentifiers(columns)
        self._table.setModel(self._dtm)
        self.data = data
        for d in data:
            self._dtm.addRow(d)
        self._pane = JScrollPane(self._table)
        self.this.add(self._pane)
        self.empty = empty
        self.popup = JPopupMenu()
        self._pane.setComponentPopupMenu(self.popup)
        inherits_popup_menu(self._pane)

        self.this.addWindowListener(self)

        self._actions = []
        self._actions.append(ExecutorAction('Remove Selected Rows', action=lambda e: self._remove_row()))
        self._actions.append(ExecutorAction('Add New Row', action=lambda e: self._add_row()))

        for action in self._actions:
            self.popup.add(action.menuitem)

    def show_option_dialog(self):
        """
        Show the option dialog

        :return: None
        """
        self.this.setForeground(Color.black)
        self.this.setBackground(Color.lightGray)
        self.this.pack()
        self.this.setVisible(True)
        self.this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)

    def _add_row(self):
        """
        Add a new row the selection

        :return: None
        """
        self._dtm.addRow(self.empty)

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
        self.this.setVisible(False)
        self._update()
        self.this.dispose()

    def _update(self):
        """
        Update the data content with the updated rows

        :return: None
        """
        del self.data[:]
        nRow = self._dtm.getRowCount()
        nCol = self._dtm.getColumnCount()
        for i in range(0, nRow):
            self.data.append([None] * nCol)
            for j in range(0, nCol):
                self.data[i][j] = self._dtm.getValueAt(i, j);


if __name__ == "__main__":
    pe = PropertyEditor(columns=['ciao', 'bao'], data=[['a', 'b'], ['c', 'd']], empty=['e1', 'e2'])
    pe.show_option_dialog()
    while True:
        time.sleep(10)
        print(pe.data)
