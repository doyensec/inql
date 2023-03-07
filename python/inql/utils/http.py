# coding: utf-8
from burp.api.montoya.http.HttpService import httpService
from burp.api.montoya.http.message.requests.HttpRequest import httpRequest

from ..globals import montoya
from ..logger import log


def request_template(url, method, headers):
    """Generate request template - the HTTP message sans body"""
    # Create basic HTTP request from the URL (don't add any headers at this point)
    http_service = httpService(url)
    req = httpRequest().withService(http_service).withMethod(method)

    if headers:
        # Set the provided headers
        log.debug("Custom headers provided: %s of them", len(headers))
        for k, v in headers:
            req = req.withAddedHeader(k, v)
        log.debug("Successfully added all headers")

    log.debug("Created the request template")
    return req


def send_request(url, headers=None, method='GET', body=None):
    log.debug("send_request(url: %s, headers: %s, method: %s, body:%s)", url, headers, method, body)
    req = request_template(url, method, headers)
    log.debug("acquired request_template")

    # Finally, add the body
    req = req.withBody(body)
    log.debug("Request that I'm sending to %s: %s", url, req.toString())

    # Send the request through Burp
    response = montoya.http().sendRequest(req).response()
    log.debug("Sent the request through Burp")

    result = response.bodyToString()
    log.debug("Response that I received from %s: %s", url, result)
    return result
