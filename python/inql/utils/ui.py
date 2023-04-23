# coding: utf-8

from burp.api.montoya.core import ByteArray
from burp.api.montoya.ui.editor import EditorOptions

from java.awt import BorderLayout, Color, Component, Container, Font
from javax.swing import BorderFactory, JButton, JLabel, JOptionPane, JPanel, JTextArea

from ..globals import callbacks, montoya
from ..logger import log


def inherits_popup_menu(element):
    """Inherits popup menu on each and every child widgets."""
    element.setInheritsPopupMenu(True)
    try:
        for e in element.getComponents():
            inherits_popup_menu(e)
    except:
        pass


def visual_error(msg):
    """Show dialog window with error message."""
    frame =  montoya.userInterface().swingUtils().suiteFrame()
    if not frame:
        log.error("Could not open a dialog window with error message (can't find Burp window): %s", msg)
        return

    log.error("Got exception and converted it to popup error: '%s'", msg)
    JOptionPane.showMessageDialog(frame, msg, "InQL error", JOptionPane.ERROR_MESSAGE)


def ui_panel(border=5):
    panel = JPanel(BorderLayout(border, border),
                  border = BorderFactory.createEmptyBorder(border, border, border, border))
    return panel


def raw_editor(read_only=None):
    """Create raw editor provide by Burp, making sure that it's created in Burp's style context."""

    if read_only:
        return montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
    return montoya.userInterface().createRawEditor()


def raw_editor_obsolete(*args, **kwargs):
    """Create raw editor for the obsolete InQL components not rewritten to Montoya API yet."""

    return callbacks.createMessageEditor(*args, **kwargs)



def show_components(el):
    for component in el.getComponents():
        el_class = el.getClass()
        comp_class = component.getClass()

        if not el_class or not comp_class:
            log.debug("qqq: fial")
            continue

        log.debug("qqq (%s): %s", el_class, comp_class)

        if isinstance(component, Container):
            show_components(component)



def ui_separator(border=5):
    return JLabel().setBorder(
        BorderFactory.createEmptyBorder(0, border, 0, border))



def ui_label(text, big=True):
    label = ui_panel(3)
    jlabel = JLabel(text)
    jlabel.setOpaque(False)
    if big:
        jlabel.setFont(Font("Sans Serif", Font.BOLD, 15))
    label.add(BorderLayout.CENTER, jlabel)
    return label


def ui_textarea(text):
    panel = ui_panel()
    textArea = JTextArea(text)

    textArea.setOpaque(False)

    textArea.setLineWrap(True)
    textArea.setWrapStyleWord(True)

    textArea.setEditable(False)

    panel.add(textArea)

    return panel


def ui_button(label, action_handler, main=False):
    button = JButton(label)
    button.addActionListener(action_handler)

    if main:
        # Draw an orange button to be consistent with Burp
        # TODO: If the user has overwritten UI styles, this will look awful - find a way to grab colors from real button
        button.setBackground(Color(255,88,18))
        button.setForeground(Color.WHITE)
        button.setFont(button.getFont().deriveFont(Font.BOLD))
        button.setBorderPainted(False)

    return button


def byte_array(string_message):
    """Converts string to Burp's byte array."""
    # https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/core/ByteArray.html
    # TODO: We might need to handle encoding ourselves (intelligent detection / fallback), but first need to identify all of places that need this
    return ByteArray.byteArray(string_message)

def add_recursive_mouse_listener(mouse_listener, component):
    for listener in component.getMouseListeners():
        # Remove previously attached listeners of the same class
        if isinstance(listener, type(mouse_listener)):
            component.removeMouseListener(listener)

    # Add a fresh listener
    log.debug("Attaching mouse listener")
    component.addMouseListener(mouse_listener)

    for child in component.getComponents():
        if isinstance(child, Component):
            add_recursive_mouse_listener(mouse_listener, child)
