# coding: utf-8
from threading import Lock
from urlparse import urlparse

from java.awt import BorderLayout, Dimension, FlowLayout
from java.awt.event import ActionListener, FocusListener, KeyAdapter, KeyEvent
from java.io import File
from java.lang import System
from javax.swing import Box, BoxLayout, JFileChooser, JPanel, JSeparator, JTextField, SwingConstants, SwingUtilities

from ..editors.propertyeditor import SettingsEditor
from ..globals import app
from ..logger import log
from ..settings.window import InQLSettingsWindow
from ..utils.decorators import single, single_with_error_handling
from ..utils.pyswing import button, label, multiline_label, panel
from .customheaders import HeadersEditor
from .introspection import analyze


class ScannerUrlField(FocusListener, KeyAdapter):
    """Textfield for the URL input. Shows a helpful hint when url is empty."""

    hint = "https://example.com/graphql"
    component = None

    def __init__(self, omnibar):
        log.debug("ScannerUrlField initiated")
        self.lock = Lock()
        self._omnibar = omnibar
        super(ScannerUrlField, self).__init__()

    def render(self):
        self.component = JTextField()
        self.component.setFocusable(True)
        self.component.putClientProperty("JTextField.placeholderText", self.hint)
        self.component.putClientProperty("JTextField.showClearButton", True)

        self.component.addKeyListener(self)
        return self.component

    @single
    def keyPressed(self, e):
        """Detect when the user presses enter in the url field"""
        if e.getKeyCode() == KeyEvent.VK_ENTER:
            log.debug("ENTER pressed in the URL field.")
            self._omnibar.run()

    def reset(self):
        log.debug("Resetting URL field.")
        self.value = ''

    @property
    def value(self):
        return self.component.getText()

    @value.setter
    def value(self, url):
        log.debug("Setting text value of the url field to '%s'", url)
        self.component.setText(url)

    def setEnabled(self, enabled):
        self.component.setEnabled(enabled)


class ScannerFileField(object):
    """Text field showing the name of currently selected text."""

    hint = "GraphQL introspection schema in JSON format"

    def __init__(self, file_action_handler):
        log.debug("ScannerFileField initiated")
        self.component = JTextField()
        self.component.putClientProperty("JTextField.placeholderText", self.hint)
        self.component.putClientProperty("JTextField.showClearButton", True)

        # causes loops, I guess focus comes back to the jtextfield after closing the window
        self.component.addFocusListener(file_action_handler)
        self.component.setMaximumSize(self.component.getPreferredSize())

    def render(self):
        self.component.setMinimumSize(Dimension(500, self.component.getPreferredSize().height))
        self.component.setPreferredSize(Dimension(500, self.component.getPreferredSize().height))
        return self.component

    @property
    def value(self):
        return self.component.getText()

    @value.setter
    def value(self, val):
        log.debug("Setting text value of the file field to '%s'", val)
        self.component.setText(val)
        log.debug("Tried changing the text value, did it work?")

    def setEnabled(self, enabled):
        self.component.setEnabled(enabled)


class ScannerFileHandler(ActionListener, FocusListener):
    """A common handler that gets triggered when a file button or file textfield is clicked."""

    def __init__(self, omnibar):
        log.debug("ScannerFileHandler initiated")
        self.lock = Lock()
        self._omnibar = omnibar
        super(ScannerFileHandler, self).__init__()

    @single
    def open_file_chooser(self):
        """Action handler for the file chooser button and text field in the Scanner tab."""
        log.debug("Opening file chooser to select a file")
        # TODO: Filter just the .json and .graphql files by default
        picker = JFileChooser()
        picker.setCurrentDirectory(File(System.getProperty("user.home")))

        users_choice = picker.showOpenDialog(self._omnibar.component)
        if users_choice == JFileChooser.APPROVE_OPTION:
            selected_file = picker.getSelectedFile()
            log.debug("User selected the file '%s'", selected_file.getAbsolutePath())
            self._omnibar.file = selected_file.getAbsolutePath()
        else:
            log.debug("User cleared file selection")
            self._omnibar.file = ""

    def actionPerformed(self, e):
        log.debug("File button clicked, event context: %s", e)
        self.open_file_chooser()

    def focusGained(self, e):
        log.debug("File field focused")
        # Transfer focus from the initially selected element to avoid loop when the focus
        # comes back to it after closing the file chooser
        e.getComponent().transferFocus()
        self.open_file_chooser()

    def focusLost(self, _):
        log.debug("File field lost focus")


class SettingsButtonHandler(ActionListener):
    """"Action handler for the settings menu."""
#    def __init__(self):
#        log.debug("SettingsButtonHandler initiated")
#        self.lock = Lock()
#        log.debug("Lock created")
#        self.window = SettingsEditor()
#        log.debug("Settings editor added")

    @single_with_error_handling
    def actionPerformed(self, _):
        log.debug("Settings opened")
        #self.window.show()
        SwingUtilities.invokeLater(lambda: InQLSettingsWindow().setVisible(True))


class HeadersButtonHandler(ActionListener):
    """Action handler for customizing headers."""
    def __init__(self):
        log.debug("HeadersButtonHandler initiated")
        self.lock = Lock()
        self.window = HeadersEditor()

    @single_with_error_handling
    def actionPerformed(self, _):
        log.debug("Opened headers customization")
        self.window.show()


class ScannerOmnibar(ActionListener):
    """Component that bundles text boxes and buttons above the FileView"""
    url_field = None
    file_field = None
    # Current values of URL and file text fields (these are properties defined below)
    # url = ''
    # file = ''
    component = None
    main_button = None

    def __init__(self):
        log.debug("ScannerOmnibar initiated")
        self.lock = Lock()
        app.omnibar = self
        log.debug("ScannerOmnibar done")

    # TODO: This function is in a dire need of refactoring
    def render(self):
        log.debug("ScannerOmnibar.render()")

        file_action_handler = ScannerFileHandler(self)


        ## 1. First block concerning URL
        #  1.1.1 First line, left - a big text label
        first_label = label("1. Provide URL of the GraphQL endpoint", big=True)

        #  1.1.1 First line, right - the main scanner button
        self.main_button = button('Analyze', self, main=True)

        self.custom_headers_button = button('Custom Headers', self.custom_header_button_handler, main=False)
        self.settings_button = button('Settings', self.settings_button_handler)

        first_line = panel()
        first_line.add(BorderLayout.WEST, first_label)

        button_pane = JPanel(FlowLayout())
        button_pane.add(self.custom_headers_button)
        button_pane.add(self.settings_button)
        button_pane.add(self.main_button)

        first_line.add(BorderLayout.EAST, button_pane)


        #  1.2 Second line - just a single Text field for URL
        # TODO add a dropdown menu to allow the user to specify which "session" to use
        self.url_field  = ScannerUrlField(self)

        url_panel = panel(10)
        url_panel.add(BorderLayout.CENTER, self.url_field.render())


        ## 2. Second block concerning file input

        #  2.1 First line - a big text label
        file_label = label("2. (Optional) Provide an introspection schema as a file (JSON)", big=True)

        file_label_panel = panel()
        file_label_panel.add(file_label)

        #  2.2 Second line - a help line / explainer in a smaller text
        file_explainer = multiline_label(
            "InQL can query schema directly from GraphQL server. "
            "If a server does not allow introspection functionality, provide schema as a file (in JSON format). "
            "URL still needs to be provied to generate sample queries.")

        #  2.3.1 File field on the left
        file_button = button("Select file ...", file_action_handler)

        #  2.3.2 Text field showing the selected file path (near the file field)
        self.file_field = ScannerFileField(file_action_handler)

        file_panel = panel(0)
        file_panel.setLayout(BoxLayout(file_panel, BoxLayout.LINE_AXIS))
        file_panel.add(Box.createRigidArea(Dimension(10, 0)))
        file_panel.add(file_button)
        file_panel.add(Box.createRigidArea(Dimension(10, 0)))
        file_panel.add(self.file_field.render())
        file_panel.add(Box.createHorizontalGlue())


        ## 3. Put everything together

        #  3.1 A horizontal separator line between the blocks

        separator = JSeparator()
        separator.setOrientation(SwingConstants.HORIZONTAL)
        separator_panel = panel(3)
        separator_panel.add(separator)

        #  3.2 Combine all elements side to side with Box layout

        self.component = panel(0)
        self.component.setLayout(BoxLayout(self.component, BoxLayout.PAGE_AXIS))

        self.component.add(first_line)
        self.component.add(url_panel)
        self.component.add(separator_panel)
        self.component.add(file_label_panel)
        self.component.add(file_explainer)
        self.component.add(file_panel)

        combined_panel = panel(10)
        combined_panel.add(self.component)
        return combined_panel


    @single_with_error_handling
    def run(self):
        """Action handler for the run button (also triggered by Enter in the URL field)."""
        # I think it makes sense to never clear the URL field, as it is convenient
        # to have it stay, e.g. if user wants to send another request with different headers.
        #
        # File field on the other hand, has to be cleared every time it has been successfully read
        # and parsed (if it wasn't parsed correctly, it is useful to see which file was selected
        # in case there was a mistake).
        #
        # This can be changed according to the user feedback.
        if not self.url:
            log.error("URL not provided")
            raise Exception("URL not provided")

        try:
            log.debug("URL to be scanned: %s" % self.url)

            domain = urlparse(self.url).netloc
            log.debug("The domain is: %s" % domain)

            if domain in app.custom_headers[app.session_name]:
                log.debug("The URL has some custom headers set")
                analyze(self.url, self.file, headers=app.custom_headers[app.session_name][domain])
            else:
                log.debug("The URL has not set any custom headers, setting headers=none")
                analyze(self.url, self.file)
        except Exception as e:
            # analyze() is running in a separate thread and doing it's own error handling, don't raise exceptions here
            log.error(e)
            log.error("File couldn't be analyzed properly.")

    @single
    def run_from_burp(self, url, headers):
        """Action handler that gets executed when request is sent to InQL Scanner through context menu."""

        log.debug("Received introspection analysis request from context menu.")

        self.url = url
        # self.file = None
        self.file = ''

        try:
            analyze(url, headers=headers)
        except:
            log.error("Couldn't process introspection query.")

    def actionPerformed(self, _):
        """Handler called by Burp when the Run button is clicked."""
        log.debug("Run button pressed")
        self.run()

    @property
    def url(self):
        return self.url_field.value

    @url.setter
    def url(self, text):
        log.debug("Set selected url to '%s'", text)
        self.url_field.value = text
        self.focus_to_url()

    def focus_to_url(self):
        log.debug("requestFocusInWindow: main tab to scanner")
        app.main_tab.panel.getParent().setSelectedComponent(app.main_tab.panel)
        app.main_tab.pane.setSelectedComponent(app.scanner_tab)

        #self.url_field.component.requestFocusInWindow()
        self.url_field.component.requestFocus()

    @property
    def file(self):
        return self.file_field.value

    @file.setter
    def file(self, filename):
        log.debug("Set selected file to '%s'", filename)
        self.file_field.value = filename

    def custom_header_button_handler(self, _):
        HeadersEditor.get_instance(app.session_name)
        log.debug("Working")

    def settings_button_handler(self, _):
        log.debug("Opening settings window")
        SwingUtilities.invokeLater(lambda: InQLSettingsWindow().setVisible(True))

    def set_busy(self, busy):
        """Set the busy state of the UI."""
        if busy:
            log.debug("Setting scanner UI to busy state")
            self.main_button.setText("Loading ...")
        else:
            log.debug("Setting scanner UI to idle state")
            self.main_button.setText("Analyze")

        self.custom_headers_button.setEnabled(not busy)
        self.main_button.setEnabled(not busy)
        self.url_field.setEnabled(not busy)
        self.file_field.setEnabled(not busy)
