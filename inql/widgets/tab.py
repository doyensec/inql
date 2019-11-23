from __future__ import print_function
import platform

if platform.system() == "Java":
    # JAVA GUI Import
    from java.awt import Color, BorderLayout
    from javax.swing import (JFrame, JPanel, JPopupMenu, JFileChooser)
    from java.lang import System
    from java.io import File

    import os
    from inql.actions.executor import ExecutorAction
    from inql.actions.flag import FlagAction
    from inql.actions.browser import BrowserAction
    from inql.introspection import init
    from inql.constants import *
    from inql.widgets.omnibar import Omnibar
    from inql.widgets.fileview import FileView

    class AttrDict(dict):
        def __init__(self, *args, **kwargs):
            super(AttrDict, self).__init__(*args, **kwargs)
            self.__dict__ = self


    def inheritsPopupMenu(element):
        element.setInheritsPopupMenu(True)
        try:
            for e in element.getComponents():
                inheritsPopupMenu(e)
        except:
            pass


    class GraphQLPanel():
        def __init__(self, actions=[], restore=""):
            self.actions = actions
            self.action_loadplaceholder = FlagAction(
                text_true="Disable Load placeholders",
                text_false="Enable Load placeholders")
            self.actions.append(self.action_loadplaceholder)
            self.actions.append(BrowserAction())
            self.actions.append(ExecutorAction("Load", self.loadurl))
            self.actions = [a for a in reversed(self.actions)]

            self.this = JPanel()
            self.this.setLayout(BorderLayout())            
            self.omnibar = Omnibar(
                hint=DEFAULT_LOAD_URL,
                label="Load",
                action=self.loadurl)
            self.this.add(BorderLayout.PAGE_START, self.omnibar.this)
            self.fileview = FileView(
                dir=os.getcwd(),
                filetree_label="Queries, Mutations and Subscriptions",
                payloadview_label="Query Template")
            self.this.add(BorderLayout.CENTER, self.fileview.this)
            self.fileview.addTreeListener(self.treeListener)

            self.popup = JPopupMenu()
            self.this.setComponentPopupMenu(self.popup)
            inheritsPopupMenu(self.this)

            for action in self.actions:
                self.popup.add(action.menuitem)

        def treeListener(self, e):
            # load selected file into textarea
            try:
                host = [str(p) for p in e.getPath().getPath()][1]
                fname = os.path.join(*[str(p) for p in e.getPath().getPath()][1:])
                f = open(fname, "r")
                payload = f.read()
                for action in self.actions:
                    action.ctx(host=host, payload=payload, fname=fname)
            except IOError:
                pass

        def filepicker(self):
            fileChooser = JFileChooser()
            fileChooser.setCurrentDirectory(File(System.getProperty("user.home")))
            result = fileChooser.showOpenDialog(self.this)
            isApproveOption = result == JFileChooser.APPROVE_OPTION
            if isApproveOption:
                selectedFile = fileChooser.getSelectedFile()
                self.omnibox.showingHint = False
                self.url.setText(selectedFile.getAbsolutePath())
            return isApproveOption

        def loadurl(self, evt):
            target = self.omnibar.getText().strip()
            if target == DEFAULT_LOAD_URL:
                if self.filepicker():
                    self.loadurl(evt)
            elif target.startswith('http://') or target.startswith('https://'):
                print("Quering GraphQL schema from: %s" % target)
                run(self, target, self.action_loadplaceholder.enabled, "URL")
            elif not os.path.isfile(target):
                if self.filepicker():
                    self.loadurl(evt)
            else:
                print("Loading JSON schema from: %s" % target)
                run(self, target, self.action_loadplaceholder.enabled, "JSON")


    def run(self, target, load_placeholer, flag):
        if flag == "JSON":
            if load_placeholer:
                args = {"schema_json_file": target, "detect": True, "key": None, "proxy": None, "target": None}
            else:
                args = {"schema_json_file": target, "detect": "", "key": None, "proxy": None, "target": None}
        else:
            if load_placeholer:
                args = {"target": target, "detect": True, "key": None, "proxy": None, "schema_json_file": None}
            else:
                args = {"target": target, "detect": "", "key": None, "proxy": None, "schema_json_file": None}

        # call init method from Introspection tool
        init(AttrDict(args))
        self.fileview.filetree.refresh()
        return
else:
    print("Load this file inside jython, if you need the stand-alone tool run: Introspection.py")

if __name__ == "__main__":
    import os, tempfile
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
