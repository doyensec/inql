# coding: utf-8
from urlparse import urlparse

from burp.api.montoya.http.HttpService import httpService
from burp.api.montoya.http.message.requests.HttpRequest import httpRequest

from ..globals import montoya
from ..logger import log


class Request(object):
    def __init__(self, mock=False):
        self.mock = mock
        self.template = None

    def __call__(self, method, url, data=None, headers=None, cookies=None):
        """Mimic the requests library's 'request' function, but use Burp's HTTP API instead of the requests library."""

        http_service = httpService(url)
        path = urlparse(url).path
        request = httpRequest().withService(http_service).withMethod(method).withPath(path)

        # Set headers
        headers = headers or {}
        for header, value in headers.items():
            request = request.withAddedHeader(header, value)

        # Set cookies
        cookies = cookies or {}
        cookie_string = "; ".join(["{}={}".format(name, value) for name, value in cookies.items()])
        if cookie_string:
            request = request.withAddedHeader("Cookie", cookie_string)

        # Save the template of the request (this gets dropped as a file in the Scanner's fileview)
        self.template = request.toString()
        log.debug("The request template is: {0}".format(self.template))

        # If we're mocking, just return the template and raise an Exception
        if self.mock:
            log.debug("Mocking the request, so we're not actually gonna send it.")
            raise Exception("Not actually gonna send a real request, we were just building the template.")
        log.debug("Not mocking, so we're gonna send the request.")

        # Set request body
        if data is not None:
            request = request.withBody(data)
        log.debug("The request is: {0}".format(request.toString()))

        # Send request and get response
        response = montoya.http().sendRequest(request).response()

        # Parse response
        response_headers = {}
        for header in response.headers():
            log.debug("Header is -> {0}: {1}".format(header.name(), header.value()))
            response_headers[header.name()] = header.value()
        response_cookies = parse_cookies(response_headers.get("Set-Cookie", ""))
        response_body = response.bodyToString()
        log.debug("The response is: {0}".format(response_body))

        return Response(response.statusCode(), response_headers, response_body, response_cookies)


class Response(object):
    """Mimic the requests library's Response object."""
    def __init__(self, status_code, headers, text, cookies):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.cookies = cookies

    def json(self):
        # This implementation assumes that the response body is JSON
        import json
        return json.loads(self.text)

def parse_cookies(cookie_string):
    log.debug("Parsing cookies from string: {0}".format(cookie_string))
    cookies = {}
    if cookie_string:
        for cookie in cookie_string.split(";"):
            # cookie is in the format: name=value; ...; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; HttpOnly
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                cookies[name.strip()] = value.strip()
    log.debug("Parsed cookies: {0}".format(cookies))
    return cookies
