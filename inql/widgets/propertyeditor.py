import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from inql.actions.executor import ExecutorAction
from javax.swing import JFrame, JTable, JScrollPane, JPopupMenu
from java.awt import Color
from javax.swing.table import DefaultTableModel
from inql.utils import inheritsPopupMenu
from java.awt.event import WindowAdapter
import time

class PropertyEditor(WindowAdapter):
    def __init__(self, text="Property Editor", columns=[], data=[], empty=[]):
        self.this = JFrame(text)
        self.table = JTable()
        self.dtm = DefaultTableModel(0, 0)
        self.dtm.setColumnIdentifiers(columns)
        self.table.setModel(self.dtm)
        self.data = data
        for d in data:
            self.dtm.addRow(d)
        self.pane = JScrollPane(self.table)
        self.this.add(self.pane)
        self.empty = empty
        self.popup = JPopupMenu()
        self.pane.setComponentPopupMenu(self.popup)
        inheritsPopupMenu(self.pane)

        self.this.addWindowListener(self)

        self.actions = []
        self.actions.append(ExecutorAction('Remove Selected Rows', action=lambda e: self.remove_row()))
        self.actions.append(ExecutorAction('Add New Row', action=lambda e: self.add_row()))

        for action in self.actions:
            self.popup.add(action.menuitem)

    def show_option_dialog(self):
        self.this.setForeground(Color.black)
        self.this.setBackground(Color.lightGray)
        self.this.pack()
        self.this.setVisible(True)
        self.this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)

    def add_row(self):
        self.dtm.addRow(self.empty)

    def remove_row(self):
        rows = self.table.getSelectedRows()
        for i in range(0, len(rows)):
            self.dtm.removeRow(rows[i] - i)

    def windowClosing(self, evt):
        self.this.setVisible(False)
        self.update()
        self.this.dispose()

    def update(self):
        del self.data[:]
        nRow = self.dtm.getRowCount()
        nCol = self.dtm.getColumnCount()
        for i in range(0, nRow):
            self.data.append([None] * nCol)
            for j in range(0, nCol):
                self.data[i][j] = self.dtm.getValueAt(i, j);


if __name__ == "__main__":
    pe = PropertyEditor(columns=['ciao', 'bao'], data=[['a', 'b'], ['c', 'd']], empty=['e1', 'e2'])
    pe.show_option_dialog()
    while True:
        time.sleep(10)
        print(pe.data)
