import platform

if platform.system() != "Java":
    print("Load this file inside Burp Suite/jython, if you need the stand-alone tool run: inql")
    exit(-1)

import os
from javax.swing import JSplitPane, JFrame
from java.awt import BorderLayout, Color

from filetree import FileTree
from payloadview import PayloadView

class FileView:
    def __init__(self, dir=None, filetree_label=None, payloadview_label=None):
        if not dir: dir = os.getcwd()
        self.filetree = FileTree(dir=dir, label=filetree_label)
        self.payloadview = PayloadView(label=payloadview_label)
        self.this = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                           self.filetree.this, self.payloadview.this)
        self.this.setOneTouchExpandable(True)
        self.this.setDividerLocation(300)
        self.filetree.tree.addTreeSelectionListener(self.treeListener)
        self.this.getRightComponent().setVisible(False)

    def treeListener(self, e):
        try:
            with open(os.path.join(*[str(p) for p in e.getPath().getPath()][1:]), 'r') as f:
                self.payloadview.refresh(f.read())
                self.this.getRightComponent().setVisible(True)
                self.this.setDividerLocation(0.25)
        except IOError:
            pass


if __name__ == "__main__":
    frame = JFrame("FileView")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(FileView().this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)