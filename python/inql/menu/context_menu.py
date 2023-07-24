# coding: utf-8

from burp.api.montoya.ui.contextmenu import ContextMenuItemsProvider

from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import JMenuItem, JPopupMenu

from ..globals import app, montoya
from ..logger import log
from ..utils.graphql import is_query
from ..utils.ui import visual_error


class SendFromInQL(MouseAdapter):
    def __init__(self, request, include_scanner=False):
        log.debug("Attaching new context menu handler")
        self.request = request

        self.popup = JPopupMenu()
        self.popup.add(SendToIntruder(request))
        self.popup.add(SendToRepeater(request))
        self.popup.addSeparator()
        if include_scanner:
            self.popup.add(ScannerMenuItem(request))
        self.popup.add(AttackerMenuItem(request))
        self.popup.add(GraphiqlMenuItem(request))

    def mousePressed(self, event):
        log.debug("Showing the right click menu")
        if event.button == MouseEvent.BUTTON3:
            self.popup.show(event.getComponent(), event.getX(), event.getY())




class ContextMenuItem(ActionListener, JMenuItem):
    """Action Listener - listens for clicks inside the context menu."""

    # The menu item text
    description = ""

    def __init__(self, request):
        log.debug("Context menu item initialized")
        super(ContextMenuItem, self).__init__(self.description)

        self.request = request
        self.addActionListener(self)

    @property
    def headers(self):
        log.debug("Getting headers")
        log.debug("Request: %s", self.request)
        log.debug("Headers: %s", self.request.headers())
        log.debug("[Headers] %s", [(header.name(), header.value()) for header in self.request.headers()])
        return [(header.name(), header.value()) for header in self.request.headers()
                    if header.name()[0] != ":"]

    @property
    def httpservice(self):
        return self.request.httpService()

    @property
    def url(self):
        return self.request.url()

    def actionPerformed(self, event):
        """Called when a menu item gets clicked."""
        log.debug("Menu item click handler fired: %s", event)
        # TODO: Make sure request is GraphQL before firing event
        self.handler(event)

    # This has to be defined in subclasses
    def handler(self, _):
        log.debug("works")


class ScannerMenuItem(ContextMenuItem):
    description = "Generate queries with InQL Scanner"

    def handler(self, _):
        app.omnibar.run_from_burp(self.url, self.headers)


class AttackerMenuItem(ContextMenuItem):
    description = "Batch attack with InQL Attacker"

    def handler(self, _):
        log.debug("fired the handler")
        app.attacker.send_to(self.url, self.request)
        log.debug("successfully fired the handler")


class GraphiqlMenuItem(ContextMenuItem):
    description = "Open in GraphiQL (embedded web IDE)"

    def handler(self, _):
        visual_error("GraphiQL support not implemented yet.")

class SendToIntruder(ContextMenuItem):
    description = "Send to Intruder"

    def handler(self, _):
        montoya.intruder().sendToIntruder(self.request)


class SendToRepeater(ContextMenuItem):
    description = "Send to Repeater"

    def handler(self, _):
        montoya.repeater().sendToRepeater(self.request)



class ContextMenu(ContextMenuItemsProvider):
    """Global context menu that appears on right-click in various Burp Suite locations."""
    menu_entries = (
        ScannerMenuItem,
        AttackerMenuItem,
        GraphiqlMenuItem
    )

    # TODO: Right now each menu item gets its own request. Is it pointer or a full copy?
    def provideMenuItems(self, ctx):
        """
        Invoked by Burp Suite when the user requests a context menu anywhere in the user interface.

        ctx: ContextMenuEvent, https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/contextmenu/ContextMenuEvent.html
        Returns: A list of custom menu items (which may include sub-menus, checkbox menu items, etc.) that should be displayed.
        """
        log.debug("provideMenuItems fired")
        request = self.__rr_from_ctx(ctx)
        log.debug("Context menu successfully identified the selected request")
        if not request:
            return []

        if not is_query(request.bodyToString()):
            log.debug("Context menu not added, because couldn't detect GraphQL content in request")
            return []

        return [entry(request) for entry in self.menu_entries]


    def __rr_from_ctx(self, ctx):
        # Right now we don't show menu if more than one request / HTTP message / scan issue has been selected
        invocation = ctx.invocationType()

        if invocation.containsScanIssues():
            log.debug("Context menu invocation with scan issues")
            issues = ctx.selectedIssues()
            log.debug("there are %s issues", len(issues))
            if len(issues) == 1:
                rrs = issues[0].requestResponses()
                if rrs:
                    log.debug("There are %s rrs", len(rrs))
                    return rrs[0].request()
                log.warn("Couldn't extract request from the selected issue.")
            else:
                log.debug("Not showing the menu, because %s issues have been selected instead of 1", len(issues))

        if invocation.containsHttpRequestResponses():
            log.debug("Context menu invocation with HTTP request-responses")
            rrs = ctx.selectedRequestResponses()
            if len(rrs) == 1:
                log.debug("Found the selected request response")
                return rrs[0].request()
            log.debug("Not showing the menu, because %s request-responses have been selected instead of 1", len(rrs))

        if invocation.containsHttpMessage():
            log.debug("Context menu invocation with HTTP messages")
            # Note that the following API returns java.util.Optional
            messages = ctx.messageEditorRequestResponse().orElse(None)
            if not messages:
                log.debug("Not showing the menu, because no HTTP messages have been selected")
            else:
                log.debug("A HTTP message was selected, nice")
                return messages.requestResponse().request()

        return None
