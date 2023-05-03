# coding: utf-8

# Nice Pythonic wrappers around Java Swing components

from java.awt import (BorderLayout, Color, Dimension, FlowLayout, Font,
                      GridBagConstraints, GridBagLayout, GridLayout, Toolkit)
from javax.swing import (BorderFactory, Box, BoxLayout, ButtonGroup, JButton, JCheckBox, JComboBox, JFileChooser,
                         JFormattedTextField, JFrame, JLabel, JList, JMenu, JMenuBar, JMenuItem, JPanel, JPasswordField,
                         JPopupMenu, JProgressBar, JRadioButton, JScrollPane, JSeparator, JSlider, JSpinner,
                         JTabbedPane, JTextArea, JTextField, JToggleButton, SpinnerNumberModel, SwingConstants)
from javax.swing.event import DocumentListener

from ..logger import log


class Size(object):
    """A simple object to hold width and height."""
    def __init__(self, size=None):
        if isinstance(size, (list, tuple)):
            self.width, self.height = size
        else:
            self.width, self.height = 0, 0

    def __str__(self):
        return "%sx%s" % (self.width, self.height)

    def __repr__(self):
        return self.__str__()

    def __nonzero__(self):
        return self.width != 0 and self.height != 0

    def __bool__(self):
        return self.__nonzero__()


def panel(border=5, element=None, layout=None):
    """Create a panel with an optional layout and border.

    The border can be specified as a single number (same border on all sides),
    a list of two numbers (vertical, horizontal), or a list of four numbers
    (top, right, bottom, left).
    """
    root = JPanel(BorderLayout() if layout is None else layout)

    if isinstance(border, int) or isinstance(border, float):
        # Same border on all sides
        borders = [border, border, border, border]
    elif isinstance(border, list) or isinstance(border, tuple):
        if len(border) == 2:
            # Vertical, horizontal
            borders = [border[0], border[1], border[0], border[1]]
        elif len(border) == 4:
            # Top, right, bottom, left
            borders = border
    root.setBorder(BorderFactory.createEmptyBorder(*borders))

    if element:
        root.add(element)

    return root


def label(text, bold=False, big=False):
    """Create a label with optional big font."""
    root = JLabel(text)
    root.setOpaque(False)

    current_font = root.getFont()
    if big:
        new_size = current_font.getSize() + 5.0
        root.setFont(current_font.deriveFont(new_size).deriveFont(Font.BOLD))
        #jlabel.setFont(jlabel.getFont().deriveFont(28))#.deriveFont(Font.BOLD))
    elif bold:
        root.setFont(current_font.deriveFont(Font.BOLD))

    wrapper = panel(0)
    wrapper.add(root)
    return wrapper


def multiline_label(value=""):
    element = JTextArea(value)

    # Component is not editable and has no background
    element.setEditable(False)
    element.setOpaque(False)

    # Make text area wrap lines nicely
    element.setLineWrap(True)
    element.setWrapStyleWord(True)

    return element


def button(label, action_handler, main=False):
    btn = JButton(label)
    btn.addActionListener(action_handler)
    if main:
        # Draw an orange button to be consistent with Burp
        # TODO: If the user has overwritten UI styles, this will look awful - find a way to grab colors from real button
        btn.setBackground(Color(255,88,18))
        btn.setForeground(Color.WHITE)
        btn.setFont(btn.getFont().deriveFont(Font.BOLD))
        btn.setBorderPainted(False)
    return btn


def separator(orientation=SwingConstants.HORIZONTAL):
    return JSeparator(orientation)


##
## Input elements for forms
##
## These all should should be callable with three arguments:
##
##   - value: initial value of the element
##   - description: description of the element
##   - action_handler: callback function to be called when the element is changed (receiving 'event' argument)
##
## Always return component wrapped in flow_h to simplify layouting.
##

class InputField(object):
    """Convenience class for input fields.

    Unifies the interface of all input fields and wraps them in a JPanel.
    Remembers the type of the value and provides a getter and setter for it.
    Provides access to the underlying Swing component and JPanel wrapper.
    """
    def __init__(self, description=None, action_handler=None, value=None, disabled=False):
        self._set_value(value)
        self._description = description
        self._action_handler = action_handler
        self.disabled = disabled

    @property
    def description(self):
        return self._description + ":" if self._description else ""

    @description.setter
    def description(self, value):
        self._description = value

    def render(self):
        self.component = self._create_component()
        self.component.setEnabled(not self.disabled)
        self.wrapper = self.create_wrapper()

        if self.value:
            self.set_value(self.value)

        if self._action_handler:
            self._setup_action_listener()

        return self.wrapper

    def _create_component(self):
        raise NotImplementedError

    def _get_value(self):
        raise NotImplementedError

    def get_value(self):
        return self._value_type(self._get_value())

    def _set_value(self, value):
        """Internal setter for the value (doesn't modify the component's value)."""
        self.value = value
        self._value_type = type(value)

    def set_value(self, value):
        raise NotImplementedError

    def _setup_action_listener(self):
        # This should set self.action_handler as a proxy handler for the component
        raise NotImplementedError

    def action_handler(self, *args, **kwargs):
        # Note that action handler gets passed this object as an argument,
        # not the original event
        self._action_handler(self)

    def _create_wrapper(self):
        return [label(self.description), self.component] if self.description else [self.component]

    def create_wrapper(self):
        return flow_h(self._create_wrapper())


class ComboBox(InputField):
    def __init__(self, description=None, action_handler=None, value=None, items=None, disabled=False):
        """A styled combobox with items and default selected item.

        Items should be a list of strings.
        Value should be a string - the selected item (could be not in the list).
        """
        self.items = items
        super(ComboBox, self).__init__(description=description, action_handler=action_handler, value=value, disabled=disabled)

    def _create_component(self):
        element = JComboBox(self.items)
        return element

    def _get_value(self):
        return self.component.getSelectedItem()

    def set_value(self, value):
        return self.component.setSelectedItem(value)

    def _setup_action_listener(self):
        self.component.addActionListener(self.action_handler)


class CheckBox(InputField):
    """A styled checkbox with default value."""

    @property
    def description(self):
        return self._description

    def _create_component(self):
        element = JCheckBox(self.description, self.value)
        return element

    def _get_value(self):
        return self.component.isSelected()

    def set_value(self, value):
        return self.component.setSelected(value)

    def _setup_action_listener(self):
        self.component.addItemListener(self.action_handler)

    def _create_wrapper(self):
        return [self.component]


class Spinner(InputField):
    def __init__(self, description=None, action_handler=None, value=None, disabled=False, min=1, max=10, step=1):
        """A styled spinner with range, step size and default value"""
        self.min = min
        self.max = max
        self.step = step
        super(Spinner, self).__init__(description=description, action_handler=action_handler, value=value, disabled=disabled)

    def _create_component(self):
        element = JSpinner(SpinnerNumberModel(self.value, self.min, self.max, self.step))
        return element

    def _get_value(self):
        return self.component.getValue()

    def set_value(self, value):
        return self.component.setValue(value)

    def _setup_action_listener(self):
        self.component.addChangeListener(self.action_handler)


# NOTE: This is an editable text field, not a label
class TextArea(InputField):
    def __init__(self, description=None, action_handler=None, value=None, disabled=False, size=None):
        """A styled text area with line wrapping and optional size"""
        self.size = Size(size) if size else Size([5, 20])
        super(TextArea, self).__init__(description=description, action_handler=action_handler, value=value, disabled=disabled)

    def _create_component(self):
        if self.size:
            element = JTextArea(self.size.height,self.size.width)
        else:
            element = JTextArea()

        # Make component editable and opaque
        element.setEditable(True)
        element.setOpaque(True)

        # Make text area wrap lines nicely
        element.setLineWrap(True)
        element.setWrapStyleWord(True)

        return element

    def _get_value(self):
        return self.component.getText()

    def set_value(self, value):
        return self.component.setText(value)

    class SimpleDocumentListener(DocumentListener):
        """Simple document listener that calls the callback on any change"""

        def __init__(self, callback):
            self.callback = callback

        def changedUpdate(self, e):
            self.callback()

        def insertUpdate(self, e):
            self.callback()

        def removeUpdate(self, e):
            self.callback()

    def _setup_action_listener(self):
        document = self.component.getDocument()
        listener = self.SimpleDocumentListener(self.action_handler)
        document.addDocumentListener(listener)

    def action_handler(self, *args, **kwargs):
        # Limit number of rows to self.size.height
        if self.component.getLineCount() > self.size.height:
            self.component.setRows(self.size.height)

        return super(TextArea, self).action_handler(*args, **kwargs)

    def _create_wrapper(self):
        if self.description:
            # Place the label above the text area
            text = label(self.description)
            return [box_v([text,
                           panel((0, 10), scrollable(self.component))])]
        else:
            return [scrollable(self.component)]



def radio_button(label, selected=False, action_handler=None):
    """A styled radiobutton with label"""
    radio = JRadioButton(label, selected)

    if action_handler:
        radio.addActionListener(action_handler)

    return radio

def text_field(placeholder='', columns=20):
    field = JTextField(placeholder, columns)
    return field

def button_group(*radiobuttons):
    group = ButtonGroup()
    for radio in radiobuttons:
        group.add(radio)
    return group

def slider(min=0, max=100, default=None, orientation=SwingConstants.HORIZONTAL):
    if default is None:
        default = (max - min) // 2

    el = JSlider(orientation, min, max, default)
    return el

def password_field(echo_char='*', action_handler=None):
    field = JPasswordField()
    field.setEchoChar(echo_char)
    if action_handler:
        field.addActionListener(action_handler)
    return field

def formatted_text_field(format, value=None, action_handler=None):
    field = JFormattedTextField(format)
    if value is not None:
        field.setValue(value)
    if action_handler:
        field.addActionListener(action_handler)
    return field


##
## Other elements
##

def progress_bar(min_value=0, max_value=100, initial_value=None, orientation=SwingConstants.HORIZONTAL):
    bar = JProgressBar(orientation, min_value, max_value)
    bar.setStringPainted(True)
    if initial_value:
        bar.setValue(initial_value)
    return bar

def tabbed_pane(tabs):
    root = JTabbedPane()
    for tab in tabs:
        root.addTab(*tab)
    return root

def scrollable(component, vertical=True, horizontal=True, preferred_size=None):
    pane = JScrollPane(component)
    if preferred_size:
        pane.setPreferredSize(Dimension(*preferred_size))

    if vertical:
        pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
    else:
        pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER)

    if horizontal:
        pane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
    else:
        pane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
    return pane

def jlist(items, action_handler=None):
    jl = JList(items)
    if action_handler:
        jl.addListSelectionListener(action_handler)
    return scroll_pane(jlist)

def toggle_button(label, selected=False):
    """A styled toggle button with label and selected state"""
    button = JToggleButton(label, selected)
    return button

def menu(title):
    return JMenu(title)

def menu_item(title, action_handler=None):
    item = JMenuItem(title)
    if action_handler:
        item.addActionListener(action_handler)
    return item

def menu_bar(*menus):
    bar = JMenuBar()
    for menu in menus:
        bar.add(menu)
    return bar

def popup_menu(*menu_items):
    menu = JPopupMenu()
    for menu_item in menu_items:
        menu.add(menu_item)
    return menu

def file_chooser(mode=JFileChooser.FILES_ONLY, action_handler=None):
    chooser = JFileChooser()
    chooser.setFileSelectionMode(mode)
    if action_handler:
        chooser.addActionListener(action_handler)
    return chooser

def flowbox(components, hgap=5, vgap=5):
    el = panel(0, layout=FlowLayout(FlowLayout.CENTER, hgap, vgap))
    for component in components:
        el.add(component)
    return el

def window(title, component):
    """Create a window (JFrame) with reasonable defaults."""
    root = JFrame(title)
    root.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

    # Add the component to the window
    root.setLayout(BorderLayout())
    root.add(component, BorderLayout.CENTER)

    # Calculate reasonable default height for the window
    preferred_size = root.getPreferredSize()
    screen_height = Toolkit.getDefaultToolkit().getScreenSize().height

    reasonable_height = min(preferred_size.height, screen_height - 50)
    root.setPreferredSize(Dimension(preferred_size.width, reasonable_height))

    # Set the maximum size of the frame to match its content
    root.setMaximumSize(Dimension(preferred_size.width, preferred_size.height))

    # Set the minimum size to something reasonable as well
    root.setMinimumSize(Dimension(preferred_size.width, 400))

    # Pack the window to fit its content
    root.pack()

    # Center the window on the screen
    root.setLocationRelativeTo(None)

    return root

# Helpers for Swing layouts

def grid_layout(rows, cols, hgap=5, vgap=5, border=0):
    return panel(border=border, layout=GridLayout(rows, cols, hgap, vgap))

def grid_h(components, gap=5):
    """Stack elements horizontally. Splits the width of the container evenly between elements.

    ! |     element1     |  |     element2     | !
    """
    root = grid_layout(1, len(components), gap, 0)
    for component in components:
        root.add(component)
    return root

def grid_v(components, gap=5):
    root = grid_layout(len(components), 1, 0, gap)
    for component in components:
        root.add(component)
    return root

def flow_h(elements, alignment='left', border=0, gap=5):
    """Flow elements horizontally. Does not take the full width of the container.

    ! | element1 |  | element 2 |                !
    """
    root = panel(border)
    alignment_map = {'left': FlowLayout.LEFT, 'right': FlowLayout.RIGHT}
    root.setLayout(FlowLayout(alignment_map[alignment], gap, 0))
    for elem in elements:
        root.add(elem)
    return root

def flow_v(elements, alignment='top', border=0, gap=5):
    root = panel(border)
    alignment_map = {'top': FlowLayout.LEADING, 'bottom': FlowLayout.TRAILING}
    root.setLayout(FlowLayout(alignment_map[alignment], 0, gap))
    for element in elements:
        root.add(element)
    return root

def box_h(elements):
    """Stack elements horizontally. Sends elements to left and right edges of the container.

    ! | element1 |                  | element2 | !
    """
    root = panel(0)
    return _stack(elements, BoxLayout.X_AXIS)

def box_v(elements, gap=5, preferred_size=None):
    """Stack elements vertically with 5px padding"""
    return _stack(elements, BoxLayout.Y_AXIS, gap, preferred_size)

def _stack(elements, axis, gap, preferred_size):
    root = panel(0)
    root.setLayout(BoxLayout(root, axis))
    for element in elements:
        root.add(element)
        strut = Box.createHorizontalStrut(gap) if axis == BoxLayout.X_AXIS else Box.createVerticalStrut(gap)
        root.add(strut)
    if preferred_size:
        root.setPreferredSize(Dimension(*preferred_size))
    return root

def box_space_v(px):
    """Add a vertical space of px pixels"""
    return Box.createVerticalStrut(px)
    #return Box.createRigidArea(Dimension(5, 0))

def gridbag(constraints=[]):
    root = panel(0, layout=GridBagLayout())
    for component, constraint in constraints:
        root.add(component, constraint)
    return root

def gridbag_constraints(gridx, gridy, gridwidth=1, gridheight=1, weightx=0.0, weighty=0.0, fill=None, anchor=None,
                           ipadx=0, ipady=0, padx=0, pady=0):
    constraints = GridBagConstraints()
    constraints.gridx = gridx
    constraints.gridy = gridy
    constraints.gridwidth = gridwidth
    constraints.gridheight = gridheight
    constraints.weightx = weightx
    constraints.weighty = weighty
    if fill is not None:
        constraints.fill = fill
    if anchor is not None:
        constraints.anchor = anchor
    constraints.ipadx = ipadx
    constraints.ipady = ipady
    constraints.insets.set(padx, pady, padx, pady)
    return constraints


def grid(elements, cols=2):
    """Arrange elements in a grid with 5px padding"""
    rows = len(elements) // cols + 1
    grid = []
    for row in range(rows):
        grid.append([])
        for col in range(cols):
            index = row * cols + col
            if index < len(elements):
                grid[row].append(elements[index])
    return vstack(*[hstack(*row) for row in grid])


def margin(element, top=5, left=5, bottom=5, right=5):
    """Add margin around an element"""
    root = panel(0)
    root.setLayout(BoxLayout(root, BoxLayout.Y_AXIS))
    root.add(Box.createVerticalStrut(top))
    row = panel(0)
    row.add(Box.createHorizontalStrut(left))
    row.add(element)
    row.add(Box.createHorizontalStrut(right))
    root.add(row)
    root.add(Box.createVerticalStrut(bottom))
    return root
