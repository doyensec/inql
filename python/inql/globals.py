# coding: utf-8
"""Provide global access to Burp's callbacks and helpers."""


class Callbacks(object):
    """Globally accessible callbacks object."""
    _upstream = None

    def init(self, burp_callbacks):
        self._upstream = burp_callbacks

    def __getattr__(self, item):
        if not self._upstream:
            raise Exception("Callbacks used before initiation!")

        return getattr(self._upstream, item)


class Helpers(object):
    """Globally accessible helpers object."""
    _upstream  = None
    _callbacks = None

    def __init__(self, burp_callbacks):
        self._callbacks = burp_callbacks

    def __getattr__(self, item):
        if not self._upstream:
            self._upstream = self._callbacks.getHelpers()

        return getattr(self._upstream, item)


class MontoyaAPI(object):
    """Globally accessible Montoya API."""
    _upstream = None

    def init(self, upstream_montoya):
        self._upstream = upstream_montoya

    def __getattr__(self, item):
        if not self._upstream:
            raise Exception("Montoya API used before initialization!")

        return getattr(self._upstream, item)

callbacks = Callbacks()
helpers   = Helpers(callbacks)
montoya   = MontoyaAPI()


# TODO: This class is dire need of error handling
class App(object):
    """Dummy class to hold app elements."""
    pass

app = App()

# This is the current selected session, by default the session is set to inql
app.session_name = "InQL"

# Custom Headers will be a dictionary of sessions. 
# Each session will be a dictionary where all the domains have a list of headers
app.custom_headers = {}
app.custom_headers[app.session_name] = {}

# Scraped Header will be a dictionary of domains with associated scraped headers 
# TODO decide if the headeres will be stored in dicsts or lists.
app.scraped_headers = {}

