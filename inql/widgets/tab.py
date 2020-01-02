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
import string

from inql.actions.executor import ExecutorAction
from inql.actions.browser import BrowserAction
from inql.introspection import init
from inql.constants import *
from inql.widgets.omnibar import Omnibar
from inql.widgets.fileview import FileView
from inql.widgets.propertyeditor import PropertyEditor
from inql.utils import inherits_popup_menu, AttrDict


class GraphQLPanel():
    """
    Compound class that represents the burp user interface tab.

    It can run standalone with limited functionalities with: jython -m inql.widgets.tab
    """
    def __init__(self, actions=[], restore=None):
        self._actions = actions
        self._load_headers = []
        self._run_config = [
            ['Proxy', None],
            ['Authorization Key', None],
            ['Load Placeholders', True],
            ['Generate HTML DOC', False],
            ['Generate Schema DOC', False],
            ['Generate Stub Queries', True]
        ]
        self._default_config = {}
        for k, v in self._run_config:
            self._default_config[k] = v
        print(self._default_config)
        self._old_config_hash = None
        self._actions.append(BrowserAction())
        self._actions.append(ExecutorAction("Configure", lambda _: self._setup()))
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
            for key, proxy, headers, target, load_placeholer, generate_html, generate_schema, generate_queries, flag in json.loads(restore):
                self._run(key, proxy, headers, target, load_placeholer, generate_html, generate_schema, generate_queries, flag)

    def _setup_headers(self):
        """
        Setup Headers callback
        :return: None
        """
        PropertyEditor.get_instance(
            text='Load Headers',
            columns=['Header', 'Value'],
            data=self._load_headers,
            empty=["X-New-Header", "X-New-Header-Value"])

    def _setup(self):
        """
        Setup callback
        :return: None
        """
        PropertyEditor.get_instance(
            text="Configure InQL",
            columns=['Property', 'Value'],
            data=self._run_config,
            actions=[
                ExecutorAction("Setup Load Headers",
                               lambda _: self._setup_headers())
            ]
        )

    def _cfg(self, key):
        """
        :param key: the key of the configuration
        :return: configuration value or default if unset
        """
        new_hash = hash(string.join([str(i) for _, i in self._run_config]))
        if self._old_config_hash != new_hash:
            self._config = {}
            for k, v in self._run_config:
                self._config[k] = v
            self._old_config_hash = new_hash
        try:
            return self._config[key]
        except KeyError:
            try:
                return self._default_config[key]
            except KeyError:
                return None

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
        elif target == 'about:config':
            self._setup()
            self._omnibar.reset()
        elif target == 'about:headers':
            self._setup_headers()
            self._omnibar.reset()
        elif target.startswith('http://') or target.startswith('https://'):
            print("Quering GraphQL schema from: %s" % target)
            self._run(target,
                      self._cfg('Authorization Key'),
                      self._cfg('Proxy'),
                      self._load_headers,
                      self._cfg('Load Placeholders'),
                      self._cfg('Generate HTML DOC'),
                      self._cfg('Generate Schema DOC'),
                      self._cfg('Generate Stub Queries'),
                      "URL")
        elif not os.path.isfile(target):
            if self._filepicker():
                self._loadurl(evt)
        else:
            print("Loading JSON schema from: %s" % target)
            self._run(target,
                      self._cfg('Authorization Key'),
                      self._cfg('Proxy'),
                      self._load_headers,
                      self._cfg('Load Placeholders'),
                      self._cfg('Generate HTML DOC'),
                      self._cfg('Generate Schema DOC'),
                      self._cfg('Generate Stub Queries'),
                      "JSON")


    def _run(self, target, key, proxy, headers, load_placeholer, generate_html, generate_schema, generate_queries, flag):
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
        self._state.append((target, key, proxy, load_placeholer, generate_html, generate_schema, generate_queries, flag))
        print((target, key, proxy, load_placeholer, generate_html, generate_schema, generate_queries, flag))
        self._omnibar.reset()
        args = {"key": key, "proxy": proxy, 'headers': headers, "detect": load_placeholer,
                "generate_html": generate_html,
                "generate_schema": generate_schema,
                "generate_queries": generate_queries,
                "target": target if flag != "JSON" else None,
                "schema_json_file": target if flag == "JSON" else None}

        # call init method from Introspection tool
        init(AttrDict(args.copy()))
        self._fileview.refresh()
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
