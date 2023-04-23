from java.awt import Color, Dimension
from java.awt.event import WindowAdapter 
from java.awt import BorderLayout, FlowLayout
from javax.swing import JFrame, JTable, JScrollPane, JPopupMenu, JTabbedPane, JLabel, JButton, JPanel, JList, ListSelectionModel, JOptionPane
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer

from java.lang import Boolean

# from inql.actions.executor import ExecutorAction

from ..globals import app
from ..logger import log

from ..utils.ui import ui_button, ui_label, ui_panel, ui_textarea, inherits_popup_menu


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
    
class NonEditableModel(DefaultTableModel):
    
    def isCellEditable(self, row, column):
        return False  # Make the column non-editable
            


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
    def get_instance(text="Header Selector"):
        """
        Singleton Method based on the text property. It tries to generate only one 
        header selector for each "session".

        :param custom_headers: it contains the current custom headers
        :param scraped_headers: it contains the current scraped headers 
        :param text: getinstance key
        :return: a new instance of HeadersEditor or a reused one.
        """        

        # Check if the instance is already present
        if text not in HeadersEditor.instances:
            log.debug("Creating the Property editor for session %s" % text)
            HeadersEditor.instances[text] = \
                HeadersEditor().__private_init__(text)

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

        # Before setting it as visible, update possible new domains
        HeadersEditor.instances[text]._update_domains()

        # In any case I have to set it visible and on top
        HeadersEditor.instances[text].this.setVisible(True)
        HeadersEditor.instances[text].this.setAlwaysOnTop(True)
        HeadersEditor.instances[text].this.setAlwaysOnTop(False)
        
        return HeadersEditor.instances[text]

    def __private_init__(self, text):
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

        self._current_domain = None

        # Create the set of custom headers associated to the session name
        app.custom_headers[text] = {}
        self._custom_headers = app.custom_headers[text]
        self._scraped_headers = app.scraped_headers

        # Data to store the state of the custom and scraped headers. 
        # Inside the private data will be stored all the headers while in the
        # Data structures we will only store the selected ones (for the custom)
        # For each domain we will store a dictionary 
        self._custom_private_data = {}
   

        # Table to display the Domains
        self._build_domains_pane()

        # Table to display the headers 
        self._build_custom_headers_pane()
        self._build_scraped_headers_pane()
        self._build_gui_tabs()

        # Adding custom headers with object boolean 
        self._augmenting_scraped_headers_data()

        return self
        
    def _build_domains_pane(self):
        domain_colum = ["Domains"]
        self._domain_table = JTable()
        # self._domain_table.setDefaultEditor(object, None);
        # self._domain_table.setDefaultRenderer(object, NonEditableColumnRenderer())  # Set the column renderer to non-editable

        self._domain_dtm = NonEditableModel(0,0)
        self._domain_dtm.setColumnIdentifiers(domain_colum)
        self._domain_table.setModel(self._domain_dtm)
        self._domain_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        self._domain_scroll_pane = JScrollPane(self._domain_table)
        self._domain_scroll_pane.setPreferredSize(Dimension(150,200))
        
        self._domain_table.getSelectionModel().addListSelectionListener(lambda _: self._domain_selection_listener())

        self._add_domain_button = ui_button("Add Domain", self._add_domain_listener, True)
        self._domain_table_panel = JPanel(BorderLayout())
        self._domain_table_panel.add(self._domain_scroll_pane, BorderLayout.CENTER)
        self._domain_table_panel.add(self._add_domain_button, BorderLayout.SOUTH)

    def _build_custom_headers_pane(self):        
        custom_headers_columns = ["Flag", "Header", "Value"]
        self._custom_headers_table = JTable()
        self._custom_headers_dtm = CustomTable(0, 0)
        self._custom_headers_dtm.setColumnIdentifiers(custom_headers_columns)
        self._custom_headers_table.setModel(self._custom_headers_dtm)

        self._custom_headers_dtm.addTableModelListener(lambda _: self._custom_headers_update())

        # Create the "Add Row" button for the second table
        self._add_custom_header = ui_button("Add Header", self._add_custom_headers_row)
        # Create the "Remove Row" button for the second table
        self._remove_custom_header = ui_button("Remove Headers", self._remove_custom_headers_row)
               
        # create the panel to hold the buttons
        self._custom_headers_button_panel = JPanel(FlowLayout())
        self._custom_headers_button_panel.add(self._add_custom_header)
        self._custom_headers_button_panel.add(self._remove_custom_header)

        self._custom_header_pane = JPanel(BorderLayout())
        self._custom_header_table_scroll_pane = JScrollPane(self._custom_headers_table)
        self._custom_header_pane.add(self._custom_header_table_scroll_pane, BorderLayout.CENTER)
        self._custom_header_pane.add(self._custom_headers_button_panel, BorderLayout.SOUTH);

    def _build_scraped_headers_pane(self):
        scraped_headers_columns = ["Header", "Value"]
        self._scraped_headers_table = JTable()
        self._scraped_headers_dtm = CustomTable(0, 0)
        self._scraped_headers_dtm.setColumnIdentifiers(scraped_headers_columns)
        self._scraped_headers_table.setModel(self._scraped_headers_dtm)
        
        self._move_scraped_headers = ui_button("Move Headers", self._move_scraped_headers_row)
        self._remove_scraped_headers = ui_button("Remove Headers", self._remove_scraped_headers_row)

        self._scraped_headers_button_panel = JPanel(FlowLayout())
        self._scraped_headers_button_panel.add(self._move_scraped_headers)
        self._scraped_headers_button_panel.add(self._remove_scraped_headers)

        self._scraped_header_pane = JPanel(BorderLayout())
        self._scraped_header_table_scroll_pane = JScrollPane(self._scraped_headers_table)
        self._scraped_header_pane.add(self._scraped_header_table_scroll_pane, BorderLayout.CENTER)
        self._scraped_header_pane.add(self._scraped_headers_button_panel, BorderLayout.SOUTH);


    def _build_gui_tabs(self):

        self.this = JFrame(self._text)
        self.this.setLayout(BorderLayout())

        self._main_headers_panel = JTabbedPane()


        self._custom_headers_label = JLabel("Custom Headers")
        self._custom_headers_label.setHorizontalAlignment(JLabel.CENTER)
        
    
        self._scraped_headers_label = JLabel("Scraped Headers")
        self._scraped_headers_label.setHorizontalAlignment(JLabel.CENTER)

        self._main_headers_panel.addTab("Custom Headers", self._custom_header_pane)
        self._main_headers_panel.addTab("Scraped Headers", self._scraped_header_pane)
        self._main_headers_panel.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

        self.this.addWindowListener(self)

        self.this.setLocation(HeadersEditor.NEW_WINDOW_OFFSET, HeadersEditor.NEW_WINDOW_OFFSET)

        
        self.this.setLayout(BorderLayout())
        self.this.add(self._domain_table_panel, BorderLayout.WEST)
        self.this.add(self._main_headers_panel, BorderLayout.CENTER)

        self.this.pack()
        self.this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)
        self.this.setVisible(True)

    def _augmenting_custom_headers_data(self):
        self._custom_headers_dtm.addRow(self._empty)
        self._custom_headers_dtm.addRow(self._empty)
        self._custom_headers_dtm.addRow(self._empty)
    
    def _augmenting_scraped_headers_data(self):
        for k in self._scraped_headers.keys():
            new_row = [k, self._scraped_headers[k]]
            self._scraped_headers_dtm.addRow(new_row)

    def _add_domain_listener(self, _):
        name = JOptionPane.showInputDialog(self, "Enter domain name: ")
        if(name != None and len(name)>0):
            if name in self._custom_headers:
                log.info("You can't add the same domain twice")
                return
            
            self._domain_dtm.addRow([name])
            self._custom_headers[name.encode('utf-8')] = [] # TODO check if it should be a dict or if a list is fine
            

    def _domain_selection_listener(self):
        log.info("Domain selection listener")

        # get selected domain
        selected_row_number = self._domain_table.getSelectedRow()
        selected_domain = str(self._domain_dtm.getValueAt(selected_row_number, 0)).lower()
        log.debug("Selected row: " + selected_domain)

        #update the current domain
        self._current_domain = None

        # get custom domains
        self._custom_headers_dtm.setRowCount(0);
        log.debug(self._custom_private_data.keys())
        if selected_domain in self._custom_private_data.keys():
            log.debug("The selected domain is in the custom private data")
            # add the domains to the table
            for header in self._custom_private_data[selected_domain]:
                new_header = []
                new_header.append(self._custom_private_data[selected_domain][header])
                header = header.split(":")
                for elem in header:
                    new_header.append(elem)
                    
                log.debug("New header to add is: ")
                log.debug(new_header)
                self._custom_headers_dtm.addRow(new_header)

        # get scraped domain
        self._scraped_headers_dtm.setRowCount(0)
        if selected_domain in self._scraped_headers.keys():
            log.debug("Selected domain is in scraped headers")
            for header in self._scraped_headers[selected_domain]:
                log.debug("Scraped header to add is: %s: %s" % (header, self._scraped_headers[selected_domain][header]))
                new_header = []
                new_header.append(header)
                new_header.append(self._scraped_headers[selected_domain][header])
                # header = header.split(":")
                # for elem in header:
                #     new_header.append(elem)
                    
                log.debug("New header to add is: ")
                log.debug(new_header)
                self._scraped_headers_dtm.addRow(new_header)

        self._current_domain = selected_domain



    def _add_custom_headers_row(self, _):
        """
        Add a new row the selection

        :return: None
        """
        if(self._current_domain == None):
            log.debug("You can't add a new line without having selected a domain")
            return
        self._custom_headers_dtm.addRow(self._empty)
        self._custom_headers_update()

    def _remove_custom_headers_row(self, _):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._custom_headers_table.getSelectedRows()
        for i in range(0, len(rows)):
            self._custom_headers_dtm.removeRow(rows[i] - i)
        
        self._custom_headers_update()
    
    def _remove_scraped_headers_row(self, _):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._scraped_headers_table.getSelectedRows()
        for i in range(0, len(rows)):
            self._scraped_headers_dtm.removeRow(rows[i] - i)
        
        # TODO add scraped header modifier
        nRow = self._scraped_headers_dtm.getRowCount()
        log.debug("Removing all the scraped headers associated to this domain")
        self._scraped_headers[self._current_domain] = {}

        for i in range(0, nRow):
            name = str(self._scraped_headers_dtm.getValueAt(i, 0)).lower()
            value = str(self._scraped_headers_dtm.getValueAt(i, 1)).lower()
            self._scraped_headers[self._current_domain][name] = value
            

    
    def _move_scraped_headers_row(self, _):
        """
        Remove all the selected rows from the selection
        :return:
        """
        rows = self._scraped_headers_table.getSelectedRows()
        log.debug("The selected rows are:")
        log.debug(rows)

        cols = self._scraped_headers_table.getColumnCount()

        for i in range(0, len(rows)):
            row_to_move = [False]
            for j in range(cols):
                row_to_move.append(self._scraped_headers_dtm.getValueAt(rows[i] - i, j))
            
            log.debug("Adding new row: %s" % row_to_move)
            self._custom_headers_dtm.addRow(row_to_move)
            self._scraped_headers_dtm.removeRow(rows[i] - i)
        self._custom_headers_update()
    
    def _update_domains(self):
        """
        Checks the content of the Domains table and adds all the domains that are in the scraped headers but not in the
        domain table
        """

        for domain in self._scraped_headers:
            log.debug("Considered domain: %s" % domain)
            if(domain != None and len(domain)>0):
                if domain in self._custom_headers:
                    log.debug("Domain already present")
                    continue
            
            self._domain_dtm.addRow([domain])
            self._custom_headers[domain] = [] # TODO check if it should be a dict or if a list is fine


    def windowClosing(self, _):
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

        # DEBUG
        log.debug("Printing the headers at the moment of the custom headers widnows closing:")
        log.debug(self._custom_headers)
        for domain in self._custom_headers:
            log.debug(self._custom_headers[domain])

        log.debug("Custom Headers in the app")
        log.debug(app.custom_headers)



    def _custom_headers_update(self):
        """
        Update the data content with the updated rows

        The old state, stored in self._private_data, is updated. 
        Depending on the presence or not of the dest_data structure, 
        the updates are stored either there or in the self._src_data

        :return: None
        """
        if(self._current_domain == None):
            log.debug("You can't add a new line without having selected a domain")
            return
        
        del self._custom_headers[self._current_domain][:]
        
        nRow = self._custom_headers_dtm.getRowCount()
        nCol = self._custom_headers_dtm.getColumnCount()
        log.debug("Removing all the custom private data associated to this domain")
        self._custom_private_data[self._current_domain] = {}
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
            log.debug("The idx is: %s" % idx)
            self._custom_private_data[self._current_domain][idx] = new_row[0]
            log.debug("self._private_data[%s] = %s" % (new_row[1:], new_row[0]))
            
            # Adding the new row to the private headers to be displayed
            if new_row[0] == True:
                self._custom_headers[self._current_domain].append(new_row[1:])
    
    def _scraped_headers_update(self):
        """
        Update the data content with the updated rows

        The old state, stored in self._private_data, is updated. 
        Depending on the presence or not of the dest_data structure, 
        the updates are stored either there or in the self._src_data

        :return: None
        """
        # log.debug("Updating the model")
        # if self._dest_data:
        #     del self._dest_data[:]
        # else:
        #     del self._src_data[:]
        
        if(self._current_domain == None):
            log.debug("You can't add a new line without having selected a domain")
            return
        
        nRow = self._scraped_headers_dtm.getRowCount()
        nCol = self._scraped_headers_dtm.getColumnCount()
        for i in range(0, nRow):
            # Creating the new row
            new_row = [None] * nCol
            for j in range(0, nCol):
                d = str(self._scraped_headers_dtm.getValueAt(i, j)).lower()
                if d == 'none' or d == '':
                    new_row[j] = None
                elif d == 'true' or d == 't':
                    new_row[j] = True
                elif d == 'false' or d == 'f':
                    new_row[j] = False
                else:
                    try:
                        new_row[j] = int(self._scraped_headers_dtm.getValueAt(i, j))
                    except ValueError:
                        new_row[j] = self._scraped_headers_dtm.getValueAt(i, j)
            
            idx = "%s:%s" % (new_row[1], new_row[2])
            log.debug("The idx is: %s" % idx)
            self._private_data[idx] = new_row[0]
            log.debug("self._private_data[%s] = %s" % (new_row[1:], new_row[0]))
            
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
                
