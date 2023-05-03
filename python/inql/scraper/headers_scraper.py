# coding: utf-8
from threading import Lock

from urlparse import urlparse

from burp.api.montoya.proxy.http import ProxyRequestHandler, ProxyRequestReceivedAction, ProxyRequestToBeSentAction

from ..globals import app
from ..logger import log


class CustomProxyListener(ProxyRequestHandler):
    """
    This class implements a listener for the burp proxy. Every request that the proxy
    intercepts will be analyzed and its headers will be stored.
    """

    def __init__(self, scraped_headers):
        log.debug("Initializing the proxy listener for scraping headers")

        self._scraped_headers = scraped_headers

        # burp will call the processProxyMessage concurrently thus the scraped headers
        # needs to be protected by a lock
        self._lock = Lock()


    def handleRequestReceived(self, interceptedRequest):
        """
        This method is invoked before an HTTP request is received by the Proxy.
        Can modify the request.
        Can modify the annotations.
        Can control whether the request should be intercepted and displayed to the user for manual review or modification.
        Can drop the request.
        """

        # get the domain of the request
        domain = urlparse(interceptedRequest.url()).netloc
        log.debug("Domain: %s" % domain)

        if domain not in self._scraped_headers:
            self._scraped_headers[domain] = {}

        # get the headers
        headers = interceptedRequest.headers()
        log.debug("Headers:")
        log.debug(headers)

        log.debug("All the headers one by one: ")
        for h in headers:
            log.debug("Header is -> %s: %s" % (h.name(), h.value()))

            # removing connection header and host
            if h.name() == "Connection" or h.name() == "Host":
                continue

            if h.value() == None or len(h.value()) <=0:
                continue

            self._scraped_headers[domain][h.name().encode('utf-8')] = h.value().encode('utf-8')

        log.debug(self._scraped_headers[domain])

        # continue with the request
        return ProxyRequestReceivedAction.continueWith(interceptedRequest.withDefaultHeaders())


    def handleRequestToBeSent(self, interceptedRequest):
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest.withDefaultHeaders())
