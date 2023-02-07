import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import os

from java.awt import (BorderLayout, Color, Container, Dimension, Component)
from java.io import File
from java.util import Vector, Collections
from javax.swing import (BoxLayout, JFrame, JPanel, JScrollPane, JTree, JLabel)
from javax.swing.tree import (DefaultMutableTreeNode, DefaultTreeModel)


class FileTree:
    """
    TreeView widget containing a filetree
    """

    def __init__(self, dir=None, label=None):
        if not dir: dir = os.getcwd()
        if not label: label = "FileTree"
        dir = File(dir)
        self._dir = dir
        self.this = JPanel()
        self.this.setLayout(BorderLayout())

        # Add a label
        self.this.add(BorderLayout.PAGE_START, JLabel(label))

        # Make a tree list with all the nodes, and make it a JTree
        tree = JTree(self._add_nodes(None, dir))
        tree.setRootVisible(False)
        self._tree = tree

        # Lastly, put the JTree into a JScrollPane.
        scrollpane = JScrollPane()
        scrollpane.getViewport().add(tree)
        self.this.add(BorderLayout.CENTER, scrollpane)

    def refresh(self):
        """
        Refresh TreeModel when the directory is updated

        :return: None
        """
        self._tree.setModel(DefaultTreeModel(self._add_nodes(None, self._dir)))

    def _add_nodes(self, curTop, dir):
        """
        Recursive implementation to fill the tree with filenames and directories

        :param curTop: current top directory
        :param dir: next directory
        :return: None
        """
        curPath = dir.getPath()
        if os.path.isdir(curPath):
            nodePath = os.path.basename(curPath)
        curDir = DefaultMutableTreeNode(nodePath)
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
            if curPath == self._dir:
                newPath = thisObject
            else:
                newPath = os.path.join(curPath, thisObject)
            f = File(newPath)
            if f.isDirectory():
                self._add_nodes(curDir, f)
            else:
                files.addElement(thisObject)

        # Pass two: for files.
        Collections.sort(files)
        for i in xrange(0, files.size()):
            f = files.elementAt(i)
            #if f.split('.')[-1] != 'html':
            curDir.add(DefaultMutableTreeNode(files.elementAt(i)))
        return curDir

    def add_tree_selection_listener(self, listener):
        """
        Wrapper for the inner tree selection listener callback register function

        :param listener: a new listener
        :return: None
        """
        self._tree.addTreeSelectionListener(listener)


if __name__ == "__main__":
    frame = JFrame("FileTree")
    frame.setForeground(Color.black)
    frame.setBackground(Color.lightGray)
    cp = frame.getContentPane()
    cp.add(FileTree().this)
    frame.pack()
    frame.setVisible(True)
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
