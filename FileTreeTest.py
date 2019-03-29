from java.awt import (BorderLayout, Color, Container, Dimension)

from java.io import File
from java.util import Vector

from javax.swing import (BoxLayout, JFrame, JPanel, JScrollPane, JTree)
from javax.swing.event import TreeSelectionEvent
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import (DefaultMutableTreeNode, DefaultTreeModel)
import os


class FileTree:

    def listener(self, e):
        try:
            path = str(e.getPath().getParentPath().getLastPathComponent())
        except AttributeError:
            path = os.getcwd()
        sep = str(os.sep)
        target = str(e.getPath().getLastPathComponent())

        # load selected file into textarea
        location = path + sep + target
        try:
            f = open(location, "r")
            self.textarea.setText(f.read())
        except IOError:
            pass

    def __init__(self, dir, textarea):
        self.textarea = textarea
        dir = File(dir)
        self.dir = dir
        self.this = JPanel()
        self.this.setLayout(BorderLayout())

        # Make a tree list with all the nodes, and make it a JTree
        tree = JTree(self.addNodes(None, dir))
        self.tree = tree

        # Add a listener
        tree.addTreeSelectionListener(self.listener)

        # Lastly, put the JTree into a JScrollPane.
        scrollpane = JScrollPane()
        scrollpane.getViewport().add(tree)
        self.this.add(BorderLayout.CENTER, scrollpane)

    def refresh(self):
        self.tree.setModel(DefaultTreeModel(self.addNodes(None, self.dir)))

    def addNodes(self, curTop, dir):
        curPath = dir.getPath()
        curDir = DefaultMutableTreeNode(curPath)
        if curTop != None:  # should only be null at root
            curTop.add(curDir)
        ol = Vector()
        tmp = dir.list()
        for i in xrange(0, len(tmp)):
            ol.addElement(tmp[i])
        thisObject = None
        files = Vector()
        # Make two passes, one for Dirs and one for Files. This is #1.
        for i in xrange(0, ol.size()):
            thisObject = ol.elementAt(i)
            if curPath == self.dir:
                newPath = thisObject
            else:
                newPath = curPath + File.separator + thisObject
            f = File(newPath)
            if f.isDirectory():
                self.addNodes(curDir, f)
            else:
                files.addElement(thisObject)

        # Pass two: for files.
        for i in xrange(0, files.size()):
            curDir.add(DefaultMutableTreeNode(files.elementAt(i)))
        return curDir


if __name__ == "__main__":
    frame = JFrame("FileTree")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(FileTree(os.getcwd()).this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
