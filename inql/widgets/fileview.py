import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import os
import json

from javax.swing import JSplitPane, JFrame
from java.awt import BorderLayout, Color

from filetree import FileTree
from payloadview import PayloadView

class FileView:
    """
    SplitPane containing an editoresque (Sublime-alike) filetree+editor widget
    """
    def __init__(self, dir=None, filetree_label=None, payloadview_label=None):
        if not dir: dir = os.getcwd()
        self._filetree = FileTree(dir=dir, label=filetree_label)
        self._payloadview = PayloadView(label=payloadview_label)
        self.this = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                               self._filetree.this, self._payloadview.this)
        self.this.setOneTouchExpandable(True)
        self._filetree.add_tree_selection_listener(self._tree_listener)
        self.this.getRightComponent().setVisible(False)

    def _tree_listener(self, e):
        """
        Listen for tree selection adn fill the payloadview

        :param e: unused
        :return: None
        """
        try:
            fpath = os.path.join(*[str(p) for p in e.getPath().getPath()][1:])

            if fpath.endswith('.html'):
                self.this.getRightComponent().setVisible(False)
                return

            with open(fpath, 'r') as f:
                payload = f.read()
                self._payloadview.set_editable(False)
                if fpath.endswith('.query'):
                    j = json.loads(payload)
                    payload = j['query']
                    self._payloadview.set_editable(True)
                self._payloadview.refresh(payload)
                self.this.getRightComponent().setVisible(True)
                self.this.setDividerLocation(0.25)
        except IOError:
            pass

    def addTreeListener(self, action):
        """
        Add a new Tree ActionListener

        :param action: actionListener lambda
        :return:
        """
        self._filetree.add_tree_selection_listener(action)

    def addPayloadListener(self, action):
        """
        Add a new PayloadView Listener

        :param action: actionListener lambda
        :return:
        """
        self._payloadview.add_listener(action)

    def refresh(self):
        self._filetree.refresh()

if __name__ == "__main__":
    frame = JFrame("FileView")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(FileView().this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)