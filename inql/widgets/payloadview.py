from __future__ import print_function

import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

from javax.swing import JFrame, JPanel, JLabel, JScrollPane, JTextArea, JTabbedPane, JSplitPane, SwingUtilities
from javax.swing.event import DocumentListener
from java.awt import BorderLayout, Color

import json

from inql.utils import inherits_popup_menu

class _PayloadListener(DocumentListener):
    """
    PayloadListener wrapper is a java DocumentListener wrapper for python lambdas
    """
    def __init__(self, event_listener=lambda e: None, changed_update=None, remove_update=None, insert_update=None):
        self.changed_update = changed_update if changed_update else event_listener
        self.remove_update = changed_update if changed_update else event_listener
        self.insert_update = changed_update if changed_update else event_listener

    def removeUpdate(self, e):
        self.remove_update(e)

    def insertUpdate(self, e):
        self.insert_update(e)

    def changedUpdate(self, e):
        self.changed_update(e)

BaseTabbedPaneUI = JTabbedPane().getUI().getClass()

class SneakTabbedPaneUI(BaseTabbedPaneUI):
    def __init__(self, tabbed_pane):
        self.tabbed_pane = tabbed_pane

    def calculateTabAreaHeight(self, tab_placement, run_count, max_tab_height):
        if self.tabbed_pane.getTabCount() > 1:
            return self.super__calculateTabAreaHeight(tab_placement, run_count, max_tab_height)
        else:
            return 0


class PayloadView:
    """
    PayloadView is a TextView viewer and editor.
    """
    def __init__(self, payload=None, texteditor_factory=None, editable=True):
        self._idx = 0

        self._texteditor_factory = texteditor_factory
        self._textareas = {}
        self._widgets = {}

        self._listener = None

        self.this = JTabbedPane()
        self.this.setUI(SneakTabbedPaneUI(self.this))

        if payload:
            self.refresh(payload)
        self.editable = editable
        self.set_editable(editable)

    def _get_textarea(self, element):
        """
        Recursive search for a textarea in the components of a given supercomponent

        :param element: current widget.
        :return: None
        """
        try:
            if 'getDocument' in dir(element) and 'append' in dir(element) and JTextArea in element.__class__.__mro__:
                return element

            for e in element.getComponents():
                ret = self._get_textarea(e)
                if ret:
                    return ret

        except:
            return None

    def _create_texteditor(self, name=None, label=None):
        _textarea = None

        if name and name in self._widgets:
            return self._widgets[name]

        if not name:
            name = "TextArea#%s" % self._idx
            self._idx += 1

        this = JPanel()

        # Add a label
        if label:
            this.setLayout(BorderLayout())
            this.add(BorderLayout.PAGE_START, JLabel(label))

        if self._texteditor_factory:
            _texteditor = self._texteditor_factory()
            _component = _texteditor.getComponent()
            this.add(BorderLayout.CENTER, _component)
            _textarea = self._get_textarea(_component)

        if not _textarea:
            _textarea = JTextArea()
            _textarea.setColumns(20)
            _textarea.setRows(5)
            _textarea.setLineWrap(True)
            _textarea.setWrapStyleWord(True)
            _textarea.setEditable(True)
            _textarea.setName(name)
            _textarea.setSelectionColor(Color(255, 153, 51))
            _textarea.requestFocus()
            # Add textarea to a scrollable JPane
            _scrollpane = JScrollPane()
            _scrollpane.setViewportView(_textarea)
            this.add(BorderLayout.CENTER, _scrollpane)

        _textarea.setEditable(self.editable)

        self._textareas[name] = _textarea
        self._widgets[name] = this

        def on_change(evt):
            if not self._textareas[name].hasFocus():
                return
            try:
                if name == "raw":
                    SwingUtilities.invokeLater(lambda: self._refresh_queries(self._textareas['raw'].getText()))
                elif name.startswith('gql_query#'):
                    id = int(name.split("#")[1])
                    content = json.loads(self._textareas['raw'].getText())
                    if id == 0 and not isinstance(content, list):
                        content['query'] = self._textareas[name].getText()
                    else:
                        content[id]['query'] = self._textareas[name].getText()
                    SwingUtilities.invokeLater(lambda: self._textareas['raw'].setText(json.dumps(content)))
                elif name.startswith('gql_variables#'):
                    id = int(name.split("#")[1])
                    content = json.loads(self._textareas['raw'].getText())
                    if id == 0 and not isinstance(content, list):
                        content['variables'] = json.loads(self._textareas[name].getText())
                    else:
                        content[id]['variables'] = json.loads(self._textareas[name].getText())
                    SwingUtilities.invokeLater(lambda: self._textareas['raw'].setText(json.dumps(content)))
            except ValueError:
                pass # Avoid crashing for JSON not valid incompatibilities

        _textarea.getDocument().addDocumentListener(_PayloadListener(changed_update=on_change))

        return this

    def set_editable(self, editable):
        """
        Enable or Disable the editable textview

        :param editable: boolean parameter representing the editability
        :return: None
        """
        self.editable = editable
        for t in self._textareas.values():
            t.setEditable(editable)


    def _graphql_queries(self, payload):
        try:
            content = json.loads(payload)
            if not isinstance(content, list):
                content = [content]

            q = {}

            for i in range(0, len(content)):
                if any(['query' in content[i] and content[i]['query'].strip().startswith(qtype) for qtype in ['query', 'mutation', 'subscription', '{']]):
                    q[i] = content[i]

            return q
        except ValueError:
            return None

    def _refresh_raw(self, payload):
        """
        Refresh the textarea content with a new payload, if present

        :param payload:
        :return: None
        """

        if payload:
            self.this.addTab("Raw", self._create_texteditor(name="raw", label='Raw'))
            self._textareas['raw'].setText(payload)
            if self._listener:
                self.add_listener(self._listener)
            inherits_popup_menu(self.this)

    def _get_tab_component_by_name(self, name):
        for i in range(0, self.this.getTabCount()):
            if self.this.getTitleAt(i) == name:
                return self.this.getComponentAt(i)

        return None

    def _get_tab_index_by_name(self, name):
        for i in range(0, self.this.getTabCount()):
            if self.this.getTitleAt(i) == name:
                return i

        return -1

    def _refresh_queries(self, payload):
        """
        Refresh the textarea content with a new payload, if present

        :param payload:
        :return: None
        """
        graphql_tabs = []
        for i in range(0, self.this.getTabCount()):
            if self.this.getTitleAt(i).startswith("GraphQL #"):
                graphql_tabs.append(self.this.getTitleAt(i))

        if payload:
            # Check if the payload contains a GraphQL query object
            queries = self._graphql_queries(payload)
            if queries:
                # Generate and append GraphQL tab to the tabs
                for query_key in queries.keys():
                    qname = "gql_query#%s" % query_key
                    vname = "gql_variables#%s" % query_key
                    tname = "GraphQL #%s" % query_key
                    queryeditor = self._create_texteditor(name=qname, label="Query:")
                    self._textareas[qname].setText(queries[query_key]['query'])
                    variableseditor = self._create_texteditor(name=vname, label="Variables:")
                    this = self._get_tab_component_by_name(tname)
                    if tname in graphql_tabs:
                        graphql_tabs.remove(tname)
                    if not this:
                        this = JSplitPane(JSplitPane.VERTICAL_SPLIT, queryeditor, variableseditor)
                    self.this.addTab(tname, this)
                    this.setOneTouchExpandable(True)
                    this.setDividerLocation(0.66)
                    if 'variables' in queries[query_key]:
                        this.getBottomComponent().setVisible(True)
                        self._textareas[vname].setText(json.dumps(queries[query_key]['variables'], indent=4))
                    else:
                        this.getBottomComponent().setVisible(False)
                        self._textareas[vname].setText("{}")

        # Remove empty graphql tabs
        try:
            for tab in graphql_tabs:
                for i in range(0, self.this.getTabCount()):
                    if self.this.getTitleAt(i) == tab:
                        self.this.remove(i)
        except:
            # Do nothing if you cannot remove an entry
            pass

        inherits_popup_menu(self.this)

    def refresh(self, payload):
        """
        Refresh the textarea content with a new payload, if present

        :param payload:
        :return: None
        """
        self._refresh_queries(payload)
        self._refresh_raw(payload)
        inherits_popup_menu(self.this)

    def textarea(self):
        return self._textareas['raw']

    def add_listener(self, listener):
        """
        add a new listener to the textarea

        :param listener: this parameter should be a lambda or a method
        :return: None
        """
        self._listener = listener
        if 'raw' in self._textareas:
            self._textareas['raw'].getDocument().addDocumentListener(_PayloadListener(listener))


if __name__ == "__main__":
    frame = JFrame("PayloadView")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    ft = PayloadView(payload='Payload')
    ft.add_listener(lambda e: print(e))
    cp.add(ft.this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)