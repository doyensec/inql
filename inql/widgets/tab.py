import platform

if platform.system() == "Java":
    # JAVA GUI Import
    from java.awt import Component
    from java.awt import Color
    import java.awt
    import java.awt.event
    from java.awt.event import FocusListener, KeyAdapter, KeyEvent
    from javax.swing import (BoxLayout, ImageIcon, JButton, JFrame, JPanel,
                             JPasswordField, JLabel, JEditorPane, JTextField, JScrollPane, JPopupMenu,
                             SwingConstants, WindowConstants, GroupLayout, JCheckBox, JTree, JFileChooser)
    import java.lang
    from java.lang import System
    import java.io
    from java.io import File

    import javax
    from java.lang import Short, Integer
    import os
    from inql.introspection import init
    from inql.constants import *
    from filetree import FileTree

    class AttrDict(dict):
        def __init__(self, *args, **kwargs):
            super(AttrDict, self).__init__(*args, **kwargs)
            self.__dict__ = self

    class HintTextField(FocusListener, KeyAdapter):
        def __init__(self, hint='hint'):
            self.this = JTextField(hint)
            self.hint = hint
            self.showingHint = True
            self.enter_listener = None
            self.this.addFocusListener(self)
            self.this.addKeyListener(self)

        def set_enter_evt_listener(self, enter_listener):
            self.enter_listener = enter_listener

        def keyPressed(self, e):
            if self.enter_listener and e.getKeyCode() == KeyEvent.VK_ENTER:
                self.enter_listener(e)
          
        def focusGained(self, e):
            if self.getText() == "":
                self.this.setText("")
                self.showingHint = False

        def focusLost(self, e):
            if self.getText() == "":
                self.this.setText(self.hint)
                self.showingHint = True

        def getText(self):
            if self.showingHint:
                return ""
            else:
                return self.this.getText()

    def inheritsPopupMenu(element):
        element.setInheritsPopupMenu(True)
        try:
            for e in element.getComponents():
                inheritsPopupMenu(e)
        except:
            pass


    class GraphQLPanel():
        # XXX: inheriting from Java classes is very tricky. It is preferable to use
        #      the decorator pattern instead.
        def __init__(self, actions=[]):
            self.this = JPanel()
            self.actions = actions
            self.initComponents()

        def treeListener(self, e):
            # load selected file into textarea
            try:
                host = [str(p) for p in e.getPath().getPath()][1]
                fname = os.path.join(*[str(p) for p in e.getPath().getPath()][1:])
                f = open(fname, "r")
                payload = f.read()
                self.TextArea.setText(payload)
                for action in self.actions:
                    action.ctx(fname=fname, payload=payload, host=host)
            except IOError:
                pass

        def initComponents(self):
            omnibox = HintTextField(DEFAULT_LOAD_URL)
            self.omnibox = omnibox
            url = omnibox.this
            omnibox.set_enter_evt_listener(lambda evt: self.LoadurlActionPerformed(evt, url, LoadPlaceholders))
            self.url = url
            jScrollPane2 = javax.swing.JScrollPane()
            TextArea = javax.swing.JTextArea()
            self.TextArea = TextArea
            jLabel2 = javax.swing.JLabel()
            jLabel3 = javax.swing.JLabel()
            LoadPlaceholders = javax.swing.JCheckBox()
            self.LoadPlaceholders = LoadPlaceholders
            Loadurl = javax.swing.JButton()
            self.Loadurl = Loadurl
            jScrollPane3 = javax.swing.JScrollPane()
            self.FT = FileTree(os.getcwd())
            self.FT.tree.addTreeSelectionListener(self.treeListener)
            Tree = self.FT.this


            url.setName("url")
            url.setSelectionColor(java.awt.Color(255, 153, 51))

            TextArea.setColumns(20)
            TextArea.setRows(5)
            TextArea.setLineWrap(True)
            TextArea.setWrapStyleWord(True)
            TextArea.setName("TextArea")
            TextArea.setSelectionColor(java.awt.Color(255, 153, 51))
            TextArea.requestFocus()
            jScrollPane2.setViewportView(TextArea)

            jLabel2.setText("Queries, mutations and subscriptions")

            jLabel3.setLabelFor(TextArea)
            jLabel3.setText("Selected template:")

            LoadPlaceholders.setSelected(True)
            LoadPlaceholders.setText("Load template placeholders")
            LoadPlaceholders.setToolTipText("Load placeholders for the templates")
            LoadPlaceholders.setName("LoadPlaceholders")

            Loadurl.setText("Load")
            Loadurl.setToolTipText("Query a GraphQL backend (introspection)")
            Loadurl.addActionListener(
                lambda evt: self.LoadurlActionPerformed(evt, url, LoadPlaceholders))

            # Tree.setToolTipText("Select an item to load it's template")
            jScrollPane3.setViewportView(Tree)
            # JAVA GUI LAYOUT
            # --------------------
            layout = javax.swing.GroupLayout(self.this)
            self.this.setLayout(layout)
            layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                              .addContainerGap()
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                    .addGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jLabel2)
                        .addGroup(layout.createSequentialGroup()
                                  .addGap(6, 6, 6)
                                  .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 231,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGap(12, 12, 12)
                    .addGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jScrollPane2, 0, Short.MAX_VALUE, Short.MAX_VALUE)
                        .addGroup(layout.createSequentialGroup()
                                  .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                  .addComponent(LoadPlaceholders))))
                                        .addGroup(layout.createSequentialGroup() # first bar the one on top
                                                  .addComponent(url, javax.swing.GroupLayout.PREFERRED_SIZE, 421,
                                                                Short.MAX_VALUE)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(Loadurl)))
                              .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
            layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                              .addContainerGap()
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(url, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                      javax.swing.GroupLayout.DEFAULT_SIZE,
                                                      javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(Loadurl))
                              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,  # vertical spacing 
                                               0, 24)
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE) # bar over the selection
                                        .addComponent(jLabel2)
                                        .addComponent(jLabel3)
                                        .addComponent(LoadPlaceholders))
                              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, True) # FileTree and Selected Template Content, TODO: use a JSplitPane here
                                        .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 403,
                                                      Short.MAX_VALUE)
                                        .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 403,
                                                      Short.MAX_VALUE))
                              .addContainerGap())
            )

            self.popup = JPopupMenu()
            self.this.setComponentPopupMenu(self.popup)
            inheritsPopupMenu(self.this)

            for action in self.actions:
                self.popup.add(action.menuitem)


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

        def LoadurlActionPerformed(self, evt, url, LoadPlaceholders):
            target = url.getText().strip()
            if target == DEFAULT_LOAD_URL:
                if self.filepicker():
                    self.LoadurlActionPerformed(evt, url, LoadPlaceholders)
            elif target.startswith('http://') or target.startswith('https://'):
                print("Quering GraphQL schema from: %s" % target)
                run(self, target, LoadPlaceholders, "URL")
            elif not os.path.isfile(target):
                if self.filepicker():
                    self.LoadurlActionPerformed(evt, url, LoadPlaceholders)
            else:
                print("Loading JSON schema from: %s" % target)
                run(self, target, LoadPlaceholders, "JSON")


    def run(self, target, LoadPlaceholders, flag):
        if flag == "JSON":
            if LoadPlaceholders.isSelected():
                args = {"schema_json_file": target, "detect": True, "key": None, "proxy": None, "target": None}
            else:
                args = {"schema_json_file": target, "detect": "", "key": None, "proxy": None, "target": None}
        else:
            if LoadPlaceholders.isSelected():
                args = {"target": target, "detect": True, "key": None, "proxy": None, "schema_json_file": None}
            else:
                args = {"target": target, "detect": "", "key": None, "proxy": None, "schema_json_file": None}

        # call init method from Introspection tool
        init(AttrDict(args))
        self.FT.refresh()
        return
else:
    print "Load this file inside jython, if you need the stand-alone tool run: Introspection.py"

if __name__ == "__main__":
    import os, shutil, tempfile
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
