# coding: utf-8

import traceback

from burp.api.montoya.core import ByteArray
from burp.api.montoya.ui.editor import EditorOptions

from java.awt import Component, Container
from javax.swing import JOptionPane

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
    log.error(traceback.format_exc())

    frame =  montoya.userInterface().swingUtils().suiteFrame()
    if not frame:
        log.error("Could not open a dialog window with error message (can't find Burp window): %s", msg)
        return

    log.error("Got exception and converted it to popup error: '%s'", msg)
    JOptionPane.showMessageDialog(frame, msg, "InQL error", JOptionPane.ERROR_MESSAGE)


def raw_editor(read_only=None):
    """Create raw editor provide by Burp, making sure that it's created in Burp's style context."""

    if read_only:
        return montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY)
    return montoya.userInterface().createRawEditor()


def raw_editor_obsolete(*args, **kwargs):
    """Create raw editor for the obsolete InQL components not rewritten to Montoya API yet."""

    return callbacks.createMessageEditor(*args, **kwargs)


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
