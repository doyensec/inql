import platform

if platform.system() == "Java":
    # JAVA GUI Import
    from java.awt import Component
    from java.awt import Color
    import java.awt
    from javax.swing import (BoxLayout, ImageIcon, JButton, JFrame, JPanel,
                             JPasswordField, JLabel, JEditorPane, JTextField, JScrollPane,
                             SwingConstants, WindowConstants, GroupLayout, JCheckBox, JTree)
    import javax
    from java.lang import Short, Integer
    import os
    from inql.introspection import init, mkdir_p
    from filetree import FileTree

    class AttrDict(dict):
        def __init__(self, *args, **kwargs):
            super(AttrDict, self).__init__(*args, **kwargs)
            self.__dict__ = self


    class GraphQLPanel:
        # XXX: inheriting from Java classes is very tricky. It is preferable to use
        #      the decorator pattern instead.
        def __init__(self, callbacks=None, helpers=None):
            self.callbacks = callbacks
            self.helpers = helpers
            self.this = JPanel()
            self.initComponents()

        def initComponents(self):
            jLabel1 = javax.swing.JLabel()
            url = javax.swing.JTextField()
            self.url = url
            LoadJSON = javax.swing.JButton()
            self.LoadJSON = LoadJSON
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
            self.FT = FileTree(os.getcwd(),TextArea)
            Tree = self.FT.this

            jLabel1.setLabelFor(url)
            jLabel1.setText("URL or File Location:")

            url.setText("http://example.com/graphql or /tmp/schema.json")
            url.setName("url")
            url.setSelectionColor(java.awt.Color(255, 153, 51))

            LoadJSON.setText("Load JSON")
            LoadJSON.setToolTipText("Load a JSON schema from a local file")
            LoadJSON.setName("LoadJSON")
            LoadJSON.addActionListener(
                lambda evt: LoadJSONActionPerformed(self, evt, url, LoadPlaceholders))

            TextArea.setColumns(20)
            TextArea.setRows(5)
            TextArea.setLineWrap(True)
            TextArea.setWrapStyleWord(True)
            TextArea.setName("TextArea")
            TextArea.setSelectionColor(java.awt.Color(255, 153, 51))
            jScrollPane2.setViewportView(TextArea)

            jLabel2.setText("Queries, mutations and subscriptions")

            jLabel3.setLabelFor(TextArea)
            jLabel3.setText("Selected template:")

            LoadPlaceholders.setSelected(True)
            LoadPlaceholders.setText("Load template placeholders")
            LoadPlaceholders.setToolTipText("Load placeholders for the templates")
            LoadPlaceholders.setName("LoadPlaceholders")

            Loadurl.setText("Load URL")
            Loadurl.setToolTipText("Query a remote GraphQL backend (introspection)")
            Loadurl.addActionListener(
                lambda evt: LoadurlActionPerformed(self, evt, url, LoadPlaceholders))

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
                                                  .addComponent(jLabel1)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(url, javax.swing.GroupLayout.PREFERRED_SIZE, 421,
                                                                Short.MAX_VALUE)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(LoadJSON)
                                                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                  .addComponent(Loadurl)))
                              .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
            layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                              .addContainerGap()
                              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel1)
                                        .addComponent(url, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                      javax.swing.GroupLayout.DEFAULT_SIZE,
                                                      javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(LoadJSON)
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
            # --------------------


    def LoadJSONActionPerformed(self, evt, url, LoadPlaceholders):
        target = url.getText()
        if checktarget(target):
            print "Loading JSON schema from: " + target
            run(self, target, LoadPlaceholders, "JSON")
        pass


    def LoadurlActionPerformed(self, evt, url, LoadPlaceholders):
        target = url.getText()
        if checktarget(target):
            print "Quering GraphQL schema from: " + target
            run(self, target, LoadPlaceholders, "URL")
        pass


    def checktarget(target):
        if target != "http://example.com/graphql or /tmp/schema.json" and target is not None and target != "":
            return True

        return False


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
    os.chdir(tmpdir)
    frame = JFrame("Burp TAB Tester")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(GraphQLPanel().this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
    from threading import Event
    Event().wait()
