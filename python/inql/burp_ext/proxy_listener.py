from burp import IProxyListener
from inql.utils import header_decomposition

from threading import Lock

import logging

class ProxyListener(IProxyListener):
    """
    This class implements a listener for the burp proxy. Every request that the proxy
    intercepts will be analyzed and its headers will be stored.
    """

    def __init__(self, scraped_headers, callbacks, helpers):
        logging.debug("Initializing the proxy listener for scraping headers")
        
        self._scraped_headers = scraped_headers
        self._callbacks = callbacks
        self._helpers = helpers

        # burp will call the processProxyMessage concurrently thus the scraped headers 
        # needs to be protected by a lock
        self._lock = Lock()

        if helpers == None:
            logging.error("The proxy listener has been initialized without helpers, it may not be able to process requests")
        
        if callbacks == None:
            logging.error("The proxy listener has been initialized without callbacks, unable to register the listener")
        else:
            self._callbacks.registerProxyListener(self)

        logging.debug("Proxy listener initialized and registered")

    def _process_request(self, reqinfo):
        host = str(reqinfo.getUrl().getHost())
        self._lock.acquire()
        if host not in self._scraped_headers:
            logging.debug("The host was not present in the scraped headers")
            self._scraped_headers[host] = {}

        for h in reqinfo.getHeaders():
            header, _ = header_decomposition(h)
            if len(header) < 1: continue
            for h in header:
                # removing connection header
                if h == "Connection": 
                    continue
                self._scraped_headers[host][h.encode('utf-8')] = header[h].encode('utf-8')
        
        self._lock.release()
        logging.debug("Final scraped headers for host: %s" % host)
        logging.debug(self._scraped_headers[host])

    def processProxyMessage(self, messageIsRequest, message):
        """
        Implements IProxyListener method

        :param messageIsRequest: True if BURP Message is a request
        :param message: message content
        :return: None
        """

        if self._callbacks and self._helpers and messageIsRequest:
            reqinfo = self._helpers.analyzeRequest(message.getMessageInfo())
            self._process_request(reqinfo)








            
