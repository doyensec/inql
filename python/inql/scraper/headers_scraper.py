# coding: utf-8
from threading import Lock
from urlparse import urlparse

from burp.api.montoya.proxy.http import ProxyRequestHandler, ProxyRequestReceivedAction, ProxyRequestToBeSentAction

from ..globals import app
from ..logger import log
from ..globals import montoya


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


class HistoryScraper():

    def __init__(self):
        pass

    def get_scraped_headers(self, domain):
        request_list = montoya.proxy().history()

        scraped_headers = []
        set_scraped_headers = set()

        for request in request_list:

            log.debug(request)
            log.debug(type(request))
            
            if domain != urlparse(request.finalRequest().url()).netloc:
                # We want to filter request based on the domain
                continue

            headers = request.finalRequest().headers()
            
            for header in headers:

                # removing connection header and host
                # TODO Add more headers that we don't consider useful.
                if header.name() == "Connection" or header.name() == "Host":
                    continue

                if header.value() == None or len(header.value()) <=0:
                    continue

                # Avoiding adding the same header (both name and value) twice.
                scraped_header = "{}: {}".format(header.name(), header.value())
                if scraped_header not in set_scraped_headers:
                    set_scraped_headers.add(scraped_header)
                    scraped_headers.append([header.name().decode('utf-8'), header.value().decode('utf-8')])

        return scraped_headers
    
    def get_scraped_domains(self):
        request_list = montoya.proxy().history()

        domains = set()

        for request in request_list:
            domains.add(urlparse(request.finalRequest().url()).netloc)


        return sorted(domains)
    

# class CachedHistoryScraper():

#     def __init__(self) -> None:
#         # the scraped headers should track the "high level" session
#         self.last_request_index = {} # session -> number
#         self.scraped_headers = {}
#         self.set_scraped_headers = {}

#     def get_scraped_headers(self, session) -> list[list[str, str]]:
#         """
#         This function will return a list containing all the non identical headers seen
#         in the history since the last query of this function.
#         """
#         if session not in self.last_request_index:
#             self.last_request_index[session] = 0
#             # self.scraped_headers[session] = []
#             # self.set_scraped_headers[session] = set()
        
#         request_list = montoya.proxy().history()
#         request_list = request_list[self.last_request_index[session]:]

#         scraped_headers = []
#         set_scraped_headers = set()

#         for request in request_list:
#             headers = request.finalRequest().headers()
            
#             for header in headers:

#                 # removing connection header and host
#                 if header.name() == "Connection" or header.name() == "Host":
#                     continue

#                 if header.value() == None or len(header.value()) <=0:
#                     continue

#                 log.debug("The header is: ")
#                 log.debug(header.name())
#                 log.debug(header.value())
#                 log.debug()

#                 scraped_header = "{}: {}".format(header.name(), header.value())
#                 # if scraped_header not in self.set_scraped_headers[session]:
#                 #     self.set_scraped_headers[session].add(scraped_header)
#                 #     self.scraped_headers[session].append([header.name(), header.value()])

#                 if scraped_header not in set_scraped_headers:
#                     set_scraped_headers.add(scraped_header)
#                     scraped_headers.append([header.name().decode('utf-8'), header.value().decode('utf-8')])    
                
#         self.last_request_index[session] += len(request)
#         return scraped_headers





# TODO 
"""
Scraped header should be based on domain and not on the session since we cannot control 
(easily now) session switch and relate them with request. This means that scraped headers
will be agnostic from the session (which is use by the custom headers).

However, scraped headers should be list[list[str,str]]. Indeed, a dictionary based on the header name 
will easily lose all the headers with the same name but different parameters. 

To make this approach feasible, the most common headers should be removed such as:
- connection
- host
- path
- user-agent
- etc...7

"""

