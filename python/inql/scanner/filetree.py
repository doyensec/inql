# coding: utf-8
import os
from collections import namedtuple

from java.awt import BorderLayout
from java.io import File
from javax.swing import JScrollPane, JTree, UIManager
from javax.swing.event import TreeSelectionListener, TreeWillExpandListener
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel

from ..logger import log
from ..utils.pyswing import panel


class FileTreeNode(DefaultMutableTreeNode):

    def __init__(self, node):
        self._node = node
        self._name = os.path.basename(node.getPath())

        self.is_file = node.isFile()
        self.is_directory = not self.is_file

        DefaultMutableTreeNode.__init__(self, (node, self._name))

    def isLeaf(self):
        return self.is_file

    def toString(self):
        return self._name

    def listFiles(self):
        files = self._node.listFiles()
        return sorted(files, key=lambda f: (f.getName()))

    def getCanonicalPath(self):
        return self._node.getCanonicalPath()

    def getParentFile(self):
        return self._node.getParentFile()


SelectedNode = namedtuple('SelectedNode',
                          [
                            'host',
                            'version',
                            'kind',
                            'path',
                            'template',
                            'url'
                          ])


howto = """
Welcome to InQL!

A short summary of usage patterns and helpful tips is meant to go here.

Have fun,
"""


class ScannerFileTree(TreeSelectionListener, TreeWillExpandListener):
    """File tree with a list of identified queries & mutations."""

    def __init__(self, fileview):
        log.debug("ScannerFileTree initiated")
        self.fileview = fileview

        # Create the HOWTO file to get displayed on the first load
        self.create_howto()

        cwd = File(os.getcwd())

        # https://www.formdev.com/flatlaf/components/tree/
        UIManager.put("Tree.showDefaultIcons", True)
        UIManager.put("Tree.paintLines", True)
        UIManager.put("Tree.lineTypeDashed", True)
        UIManager.put("Tree.showsRootHandles", True)
        UIManager.put("Tree.rendererFillBackground", False)

        self.tree = JTree(DefaultMutableTreeNode())
        self.tree.setRootVisible(True)
        self.tree.addTreeSelectionListener(self)
        self.tree.addTreeWillExpandListener(self)

        nested_panel = panel()
        nested_panel.add(BorderLayout.CENTER, self.tree)
        scrollpane = JScrollPane()
        scrollpane.getViewport().add(nested_panel)

        self.component = panel()
        self.component.add(BorderLayout.CENTER, scrollpane)

        # On a first load open the InQL howto document
        self.show_howto()

    def render(self):
        return self.component

    def create_howto(self):
        with open("inql_howto.txt", "w") as f:
            f.write(howto)

    def show_howto(self):
        log.debug("Showing howto")
        initial_node = SelectedNode(
            host=None,
            version=None,
            kind=None,
            path=os.path.abspath('inql_howto.txt'),
            template=None,
            url=None)
        self.fileview.payloadview.load(initial_node)
        self.refresh()

    def refresh(self):
        """Refresh TreeModel when the directory is updated"""
        log.debug("Refreshing tree model")
        cwd = File(os.getcwd())

        root = FileTreeNode(cwd)
        self.model = DefaultTreeModel(root)
        self.addNodes(root, True)
        self.tree.setModel(self.model)

    def addNodes(self, root, addChildNodes):
        if root.is_file:
            return

        files = root.listFiles()
        if files is None:
            return

        directoryInsert = 0
        for i in range(len(files)):
            file = files[i]
            node = FileTreeNode(file)

            if file.isDirectory():
                root.insert(node, directoryInsert)
                directoryInsert += 1
            else:
                root.insert(node, i)

            if addChildNodes:
                self.addNodes(node, False)

    def treeWillExpand(self, e):
        if self.tree.hasBeenExpanded(e.getPath()):
            return

        path = e.getPath()

        if path.getPathCount() == 2:
            return

        node = path.getPathComponent(path.getPathCount() - 1)
        self.addNodes(node, False)

    def treeWillCollapse(self, e):
        pass

    def _build_url(self, template_path):
        with open(template_path, "r") as f:
            url = f.readline().strip()
            log.debug("Found the URL: %s", url)
        return url

    def selected(self):
        """Returns a convenient named tuple (SelectedNode) with info on selected item."""
        log.debug("Determining selected nodes in the file tree.")

        tree_path = self.tree.getSelectionPath()
        if not tree_path:
            log.debug("Asked to get selection, but I don't think anything has been selected.")
            return None

        # Here are the expected path components:
        #   1. root directory (tmpdir)
        #   2. 'example.com': domain name (the first directory that's displayed in the UI)
        #   3. '2023-03-03_202020': subfolder, corresponding to the execution time, so that we can have multiple scans per host
        #   4. 'mutations'/'queries'/'schema.json'/'request_template.txt'
        #   5. actual *.graphql files - queries / mutations

        item = tree_path.getLastPathComponent()

        if item.is_directory:
            log.debug("The selected item is a directory - skip it (%s)", item.toString())
            return None

        path = item.getCanonicalPath()

        if tree_path.getPathCount() == 5 and path.endswith('.graphql'):
            # This is a GraphQL query / mutation
            kind = item.getParentFile()
            version = kind.getParentFile()
            host = version.getParentFile()
            template = version.getCanonicalPath() + '/request_template.txt'
            url = self._build_url(template)

            return SelectedNode(
                host = host.getCanonicalPath(),
                version = version.getCanonicalPath(),
                kind = kind.getCanonicalPath(),
                path = path,
                template = template,
                url = url)

        return SelectedNode(
            host = None,
            version = None,
            kind = None,
            path = path,
            template = None,
            url = None
        )

    def valueChanged(self, _):
        """Tree selection event handler."""
        log.debug("Tree selection handler fired.")
        node = self.selected()
        if not node:
            return

        log.debug("Detected selection: %s", node)
        self.fileview.payloadview.load(node)
