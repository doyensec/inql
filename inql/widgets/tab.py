from __future__ import print_function
import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

# JAVA GUI Import
from java.awt import Color, BorderLayout
from javax.swing import (JFrame, JPanel, JPopupMenu, JFileChooser)
from java.lang import System
from java.io import File

import os
import json
from inql.actions.executor import ExecutorAction
from inql.actions.flag import FlagAction
from inql.actions.browser import BrowserAction
from inql.introspection import init
from inql.constants import *
from inql.widgets.omnibar import Omnibar
from inql.widgets.fileview import FileView
from inql.utils import inherits_popup_menu, AttrDict


class GraphQLPanel():
    """
    Compound class that represents the burp user interface tab.

    It can run standalone with limited functionalities with: jython -m inql.widgets.tab
    """
    def __init__(self, actions=[], restore=None):
        self._actions = actions
        self.action_loadplaceholder = FlagAction(
            text_true="Disable Load placeholders",
            text_false="Enable Load placeholders")
        self._actions.append(self.action_loadplaceholder)
        self.action_generate_html = FlagAction(
            text_true="Disable HTML DOC Generation",
            text_false="Enable HTML DOC Generation",
            enabled=False)
        self._actions.append(self.action_generate_html)
        self.action_generate_schema = FlagAction(
            text_true="Disable Schema DOC Generation",
            text_false="Enable Schema DOC Generation",
            enabled=False)
        self._actions.append(self.action_generate_schema)
        self.action_generate_queries = FlagAction(
            text_true="Disable STUB Queries Generation",
            text_false="Enable STUB Queries Generation")
        self._actions.append(self.action_generate_queries)
        self._actions.append(BrowserAction())
        self._actions.append(ExecutorAction("Load", self._loadurl))
        self._actions = [a for a in reversed(self._actions)]

        self.this = JPanel()
        self.this.setLayout(BorderLayout())
        self._omnibar = Omnibar(
            hint=DEFAULT_LOAD_URL,
            label="Load",
            action=self._loadurl)
        self.this.add(BorderLayout.PAGE_START, self._omnibar.this)
        self._fileview = FileView(
            dir=os.getcwd(),
            filetree_label="Queries, Mutations and Subscriptions",
            payloadview_label="Query Template")
        self.this.add(BorderLayout.CENTER, self._fileview.this)
        self._fileview.addTreeListener(self._tree_listener)
        self._fileview.addPayloadListener(self._payload_listener)

        self._popup = JPopupMenu()
        self.this.setComponentPopupMenu(self._popup)
        inherits_popup_menu(self.this)

        for action in self._actions:
            self._popup.add(action.menuitem)

        self._state = []
        if restore:
            for target, load_placeholer, generate_html, generate_schema, generate_queries, flag in json.loads(restore):
                run(self, target, load_placeholer, generate_html, generate_schema, generate_queries, flag)

    def state(self):
        """
        Tab State, used to regenerate the status after load.

        :return: the current status in JSON format, this will be saved in BURP preferences for later reuse
        """
        return json.dumps(self._state)

    def _tree_listener(self, e):
        """
        Listen to Ftree change and act on that behalf.

        :param e: get current path and set the context on every action.
        :return: None
        """
        try:
            host = [str(p) for p in e.getPath().getPath()][1]
            self._host = host
            fname = os.path.join(*[str(p) for p in e.getPath().getPath()][1:])
            self._fname = fname
            f = open(fname, "r")
            payload = f.read()
            for action in self._actions:
                action.ctx(host=host, payload=payload, fname=fname)
        except IOError:
            pass

    def _payload_listener(self, e):
        """
        Listen for Payload Change and change the context of every action accordingly.

        :param e: event change.
        :return: None
        """

        try:
            doc = e.getDocument()
            payload = {
                "query": doc.getText(0, doc.getLength())
            }
            for action in self._actions:
                action.ctx(host=self._host, payload=json.dumps(payload), fname=self._fname)
        except Exception:
            pass

    def _filepicker(self):
        """
        Run the filepicker and return if approved

        :return: boolean, true if approved
        """
        fileChooser = JFileChooser()
        fileChooser.setCurrentDirectory(File(System.getProperty("user.home")))
        result = fileChooser.showOpenDialog(self.this)
        isApproveOption = result == JFileChooser.APPROVE_OPTION
        if isApproveOption:
            selectedFile = fileChooser.getSelectedFile()
            self._omnibar.setText(selectedFile.getAbsolutePath())
        return isApproveOption

    def _loadurl(self, evt):
        """
        load url if present.

        :param evt: load url or reload itself with the same evt.
        :return: None
        """
        target = self._omnibar.getText().strip()
        if target == DEFAULT_LOAD_URL:
            if self._filepicker():
                self._loadurl(evt)
        elif target.startswith('http://') or target.startswith('https://'):
            print("Quering GraphQL schema from: %s" % target)
            self._run(target, self.action_loadplaceholder.enabled(),
                      self.action_generate_html.enabled(),
                      self.action_generate_schema.enabled(),
                      self.action_generate_queries.enabled(),
                "URL")
        elif not os.path.isfile(target):
            if self._filepicker():
                self._loadurl(evt)
        else:
            print("Loading JSON schema from: %s" % target)
            self._run(target,
                      self.action_loadplaceholder.enabled(),
                      self.action_generate_html.enabled(),
                      self.action_generate_schema.enabled(),
                      self.action_generate_queries.enabled(),
                "JSON")


    def _run(self, target, load_placeholer, generate_html, generate_schema, generate_queries, flag):
        """
        Run the actual analysis, this method is a wrapper for the non-UI version of the tool and basically calls the
        main/init method by itself.

        :param target: target URL
        :param load_placeholer: load placeholder option
        :param generate_html: generate html option
        :param generate_schema: generate schema option
        :param generate_queries: generate queries option
        :param flag: "JSON" file or normal target otherwise
        :return: None
        """
        self._state.append((target, load_placeholer, generate_html, generate_schema, generate_queries, flag))
        self.omnibar.reset()
        args = {"key": None, "proxy": None, "target": None, 'headers': [],
                "generate_html": generate_html, "generage_schema": generate_schema,
                "generate_queries": generate_queries, "detect": load_placeholer}
        if flag == "JSON":
            args["schema_json_file"] = target
        else:
            args["target"] = target

        args["detect"] = load_placeholer

        # call init method from Introspection tool
        init(AttrDict(args.copy()))
        self.fileview.filetree.refresh()
        return

if __name__ == "__main__":
    import tempfile
    tmpdir = tempfile.mkdtemp()
    from java.awt.event import ActionListener
    from javax.swing import JMenuItem

    class TestAction(ActionListener):
        def __init__(self, text):
            self.requests = {}
            self.menuitem = JMenuItem(text)
            self.menuitem.addActionListener(self)
            self.enabled = True
            self.menuitem.setEnabled(self.enabled)

        def actionPerformed(self, e):
            self.enabled = not self.enabled
            self.menuitem.setEnabled(self.enabled)

        def ctx(self, host=None, payload=None, fname=None):
            pass
    print("Changing dir to %s" % tmpdir)
    os.chdir(tmpdir)
    frame = JFrame("Burp TAB Tester")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(GraphQLPanel(actions=[TestAction("test it")]).this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
    from threading import Event
    Event().wait()
