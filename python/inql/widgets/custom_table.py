import logging
from javax.swing.table import DefaultTableModel
from java.lang import Boolean


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