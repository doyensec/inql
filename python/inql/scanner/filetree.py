# coding: utf-8
import os
from collections import namedtuple

from java.awt import BorderLayout
from java.io import File
from javax.swing import JScrollPane, JTree
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import TreeModel

from ..logger import log
from ..utils.ui import ui_panel


# TODO: A "correct" approach would be employing tree cell renderer: https://docs.oracle.com/javase/7/docs/api/javax/swing/tree/TreeCellRenderer.html
# it doesn't work for me though. All examples are in Java, so I'm probably missing something during Python translation.
# TODO: This code asks to be rewritten in Kotlin.
class NoPathPlease(File):
    """A java.io.File subclass to show basenames instead of full path names in the file tree view."""
    def __init__(self, f):
        super(NoPathPlease, self).__init__(f.toURI())

    def toString(self):
        return self.getName()

# Tree model interface: https://docs.oracle.com/javase/7/docs/api/javax/swing/tree/TreeModel.html
class ScannerFileTreeModel(TreeModel):
    def __init__(self, fileobj):
        log.debug("ScannerFileTreeModel initialization")
        self.root_element = fileobj

    def getRoot(self):
        return NoPathPlease(self.root_element)

    def getChild(self, parent, index):
        files = sorted(parent.listFiles())
        if files:
            log.debug("return %s", files[index])
            return NoPathPlease(files[index])
        return None

    def getChildCount(self, parent):
        if not parent.isDirectory():
            log.debug("'%s' is not a directory -> 0", parent)
            return 0
        files = parent.list()
        if files:
            return len(files)
        return 0

    def isLeaf(self, node):
        return not node.isDirectory()

    def getIndexOfChild(self, parent, child):
        for n, el in enumerate(sorted(parent.list())):
            if child.getName() == el:
                return n
        return -1

    # TODO: do we even need to define these?
    def valueForPathChanged(self, path, newValue):
        log.debug("valueForPathChanged(%s, %s)", path, newValue)

    def addTreeModelListener(self, listener):
        log.debug("addTreeModelListener(%s)", listener)

    def removeTreeModelListener(self, listener):
        log.debug("removeTreeModelListener(%s)", listener)


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


class ScannerFileTree(TreeSelectionListener):
    """File tree with a list of identified queries & mutations."""

    def __init__(self, fileview):
        log.debug("ScannerFileTree initiated")
        self.fileview = fileview

        # Create the HOWTO file to get displayed on the first load
        self.create_howto()

        cwd = File(os.getcwd())
        model = ScannerFileTreeModel(cwd)

        self.tree = JTree(model)
        self.tree.setRootVisible(True)
        self.tree.addTreeSelectionListener(self)

        nested_panel = ui_panel()
        nested_panel.add(BorderLayout.CENTER, self.tree)
        scrollpane = JScrollPane()
        scrollpane.getViewport().add(nested_panel)

        self.component = ui_panel()

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

    def refresh(self):
        """Refresh TreeModel when the directory is updated"""
        log.debug("Refreshing tree model")
        cwd = File(os.getcwd())
        model = ScannerFileTreeModel(cwd)
        # TODO: Do we need to do something with the old model after replacing it? Will it still occupy memory after that?
        self.tree.setModel(model)

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

        if item.isDirectory():
            log.debug("The selected item is a directory - skip it (%s)", item.getPath())
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
