# coding: utf-8
from java.awt import Color
from java.awt.event import WindowAdapter
from javax.swing import AbstractAction, JFrame, JPopupMenu, JScrollPane, JTable
from javax.swing.table import DefaultTableModel

from ..logger import log
from ..utils.ui import inherits_popup_menu


class MenuItemHandler(AbstractAction):
    """Basic menu item handler for the right-click menu in Settings and Custom Headers windows."""
    def __init__(self, name, handler):
        super(MenuItemHandler, self).__init__(name)
        self._handler = handler

    def actionPerformed(self, _):
        log.debug("Menu item handler fired")
        self._handler()


class PropertyEditor(WindowAdapter):
    title = "Property Editor"
    columns = ('Property', 'Value')
    # Data table model
    dtm = None

    def __init__(self):
        log.debug("PropertyEditor instance initialized")
        component = JFrame(self.title)
        # TODO: This should be by default, right?
        #component.setVisible(False)

        component.add(self._get_table_pane())

        component.setForeground(Color.black)
        component.setBackground(Color.lightGray)
        # TODO: "Pack sizes content so that all its sizes are at or above their preferred sizes."
        component.pack()

        # The window shouldn't be closed for real, because we will just hide it through event listener
        component.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)
        component.addWindowListener(self)

        self.component = component
        log.debug("PropertyEditor done initializing")

    def _get_table_pane(self):
        """ScrollPane, containing Table component with a right-click menu."""
        self.table = JTable()
        self.table.setModel(self._get_table_model())

        # Set up right-click menu
        popup_menu = self.__popup_menu()

        pane = JScrollPane(self.table)
        pane.setComponentPopupMenu(popup_menu)
        inherits_popup_menu(pane)

        return pane

    def __popup_menu(self):
        popup = JPopupMenu("anything?")
        log.debug("Adding context entries")
        for action in self.context_menu_entries():
            popup.add(action)
        log.debug("Added all context menu entries")
        return popup

    def get_data(self):
        """Data provider, should be defined in child class."""
        pass

    def save_data(self):
        """Save data on window close, should be defined in child class."""
        pass

    # TODO: convert to property
    def _get_table_model(self):
        self.dtm = DefaultTableModel(0, 0)
        self.dtm.setColumnIdentifiers(self.columns)

        for row in self.get_data():
            self.dtm.addRow(row)
        return self.dtm

    # TODO: convert to property if there are no issues with inheritance
    def context_menu_entries(self):
        # Add default menu entries
        return (
            MenuItemHandler('Remove Selected Rows', handler=self._remove_row),
            MenuItemHandler('Add New Row',          handler=self._add_row))

    def _remove_row(self):
        # can't just do:
        #
        #   for i in self.table.getSelectedRows():
        #       self.dtm.removeRow(i)
        #
        # because if there are multiple rows selected, their indices will decrement
        # each time one previous row gets removed
        #
        # it seems that right now only consecutive rows can be selected, if that
        # ever changes, we need to revise the algorithm
        for i, row_index in enumerate(self.table.getSelectedRows()):
            self.dtm.removeRow(row_index - i)

    def _add_row(self):
        self.dtm.addRow([])

    def show(self):
        """Show window"""
        self.component.setVisible(True)

    def hide(self):
        """Hide window"""
        self.component.setVisible(False)

    def windowClosing(self, _):
        """Handler to hijack window closing event for auto-saving the modified values."""
        self.save_data()
        self.hide()

    def __del__(self):
        # I wonder if this is enough to avoid memory leaks
        self.component.dispose()

class SettingsEditor(PropertyEditor):
    title = "Configure InQL"
    columns = ('Setting', 'Value')

    def get_data(self):
        log.debug("Settings editor trying to access data model")
        return []

    def save_data(self):
        pass

    # Overrides parent method to add additional menu entries
    def context_menu_entries(self):
        # Custom menu entries
        custom_entries = (
            MenuItemHandler("Set custom headers", handler=self._custom_headers_handler),
            MenuItemHandler("Reset all settings", handler=self._reset_settings))
        # Default menu entries
        default_entries = super(SettingsEditor, self).context_menu_entries()

        return custom_entries + default_entries

    def _custom_headers_handler(self):
        log.debug("Headers handler fired")

    def _reset_settings(self):
        log.debug("Settings reset handler fired")

class HeadersEditor(PropertyEditor):
    title = "Load Headers"
    columns = ('Header', 'Value')

    def get_data(self):
        log.debug("Headers editor trying to access data model")
        return []

    def save_data(self):
        pass
