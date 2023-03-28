# coding: utf-8
import json
import os
from datetime import datetime
from urlparse import urlparse

from gqlspection import GQLSchema
from gqlspection.introspection_query import get_introspection_query

from ..globals import app
from ..logger import log
from ..utils.decorators import threaded
from ..utils.graphql import is_valid_graphql_name
from ..utils.http import request_template, send_request
from ..utils.ui import visual_error


# TODO: Support four additional content-type options:
#   1. GET requests
#   2. application/graphql
#   3. urlencoded POST
#   4. form-data POST
def _normalize_headers(host, explicit_headers):
    """Make sure headers contain valid host and content type."""

    headers = []

    content_type_present, host_header_present = False, False
    for k, v in (explicit_headers or []):
        headers.append((k, v))

        if (k.lower() == 'content-type' and
            v.lower() in ('application/json', 'application/graphql')):
            content_type_present = True
        elif k.lower() == 'host':
            host_header_present = True

    if not content_type_present:
        headers.append(('Content-Type', 'application/json'))

    if not host_header_present:
        headers = [('Host', host)] + headers
    return headers


def query_introspection(url, headers=None):
    """
    Send introspection query (through Burp facilities) and get the GraphQL schema.
    """
    log.debug("Introspection query about to be sent")
    for version in ('draft', 'oct2021', 'jun2018'):
        # Iterate through all introspection query versions, starting from the most recent one
        log.debug("Will try to get introspection query using '%s' version from '%s'.", version, url)

        # Get the introspection query
        body = '{{"query":"{}"}}'.format(get_introspection_query(version=version))
        log.debug("acquired introspection query body")

        # Send HTTP request through Burp facilities
        response = send_request(url, headers=headers, method='POST', body=body)
        log.debug("sent the request and got the response")

        try:
            schema = json.loads(response)
            log.debug("successfully parsed JSON")
        except Exception:
            # TODO: Doesn't this mean it's not a GraphQL endpoint? Maybe early return?
            log.error("Could not parse introspection query for the url '%s' (version: %s).", url, version)
            continue

        if 'errors' in schema:
            for msg in schema['errors']:
                log.debug("Received an error from %s (version: %s): %s", url, version, msg)
            continue

        # Got successful introspection response!
        log.info("Found the introspection response with '%s' version schema.", version)
        log.debug("The received introspection schema: %s", schema)
        return schema

    # None of the introspection queries were successful
    log.error("Introspection seems disabled for this endpoint: '%s'.", url)
    raise Exception("Introspection seems disabled for this endpoint: '%s'." % url)


@threaded
def analyze(url, filename=None, headers=None):
    """
    Analyze the introspection JSON and populate GUI with results (runs async in a new thread!).

    'url' must be provided, schema_filename could be None.
    """
    try:
        _analyze(url, filename, headers)
        app.omnibar.file = ''
    except Exception as e:
        visual_error(str(e))
    finally:
        app.fileview.refresh()


# TODO: The exception handling here is all over the place. Improvements are welcome.
# TODO: Would be nice to process as much as possible, instead of failing at first exception.
def _analyze(url, filename=None, explicit_headers=None):
    host = urlparse(url).netloc
    headers = _normalize_headers(host, explicit_headers)

    if filename:
        # TODO: This needs to be tested with CRLF linebreaks and maybe other oddities
        # TODO: Add support for GraphQL schema in SDL format
        log.debug("GraphQL schema supplied as a file.")
        with open(filename) as f:
            data = f.read()
            try:
                schema = json.loads(data)
            except Exception as e:
                # TODO: Doesn't this mean it's not a GraphQL endpoint? Maybe early return?
                log.error("Could not parse introspection schema from the file '%s' (exception: %s)", filename, str(e))
                raise Exception("Could not parse introspection schema, make sure it's valid JSON GraphQL schema.")
    else:
        log.debug("GraphQL schema wil be queried from the server.")
        try:
            schema = query_introspection(url, headers)
        except Exception as e:
            # TODO: show some visual feedback here as well
            log.error("No JSON schema provided and server '%s' did not return results for the introspection query (exception: %s).", host, e)
            raise Exception("Introspection schema does not seem to be enabled on the server! Provide schema as a JSON file.")
    log.debug("GraphQL schema acquired successfully.")

    # Create report directory (example: api.example.com/2023-02-15_102254)
    date = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_dir = "{}/{}".format(host, date)
    queries_dir = os.path.join(report_dir, 'queries')
    mutations_dir = os.path.join(report_dir, 'mutations')
    try:
        os.makedirs(report_dir)
        os.makedirs(queries_dir)
        os.makedirs(mutations_dir)
    except OSError:
        # Directory already exists - unexpected, but hardly a problem
        log.warning("Failed to create a new directory for the reports '%s' - as it already exists")
    log.debug("Created the directory structure for the '%s'", url)

    # Dump request template
    template = request_template(url, method='POST', headers=headers)
    with open(os.path.join(report_dir, "request_template.txt"), "wb") as f:
        log.debug("Dumping the request template.")
        f.write(url + '\n')
        f.write(template.toString())

    # Dump JSON schema
    with open(os.path.join(report_dir, "schema.json"), "w") as schema_file:
        log.debug("Dumping JSON schema")
        schema_file.write(json.dumps(schema, indent=4, sort_keys=True))

    log.debug("About to parse the schema received from '%s'.", url)
    try:
        parsed_schema = GQLSchema(json=schema)
    except:
        log.error("Could not parse the received GraphQL schema.")
        raise Exception("Could not parse the received GraphQL schema. Validate dumped JSON manually and file a bug report if it seems correct.")

    # Write queries
    log.debug("Writing queries for the url: '%s'.", url)
    try:
        queries = parsed_schema.queries
    except:
        raise Exception("Failed to parse queries.")

    for query in queries:
        if not is_valid_graphql_name(query.name):
            # TODO: this does not warrant a popup, but it would be nice to show some kind of indication anyway
            log.error("Query with invalid GraphQL name detected: '%s'.", query.name)
            continue

        log.debug("Writing query '%s'.", query.name + '.graphql' + ' to ' + os.getcwd())
        filename = os.path.join(
            queries_dir,
            "{}.graphql".format(query.name)
        )

        try:
            parsed = query.to_string(pad=4)
        except:
            raise Exception("Failed to parse query '%s'!" % query.name)

        with open(filename, "w") as query_file:
            query_file.write(parsed)

    # Write mutations
    log.debug("Writing mutations for the url: '%s'.", url)
    try:
        mutations = parsed_schema.mutations
    except:
        raise Exception("Failed to parse mutations.")

    for mutation in mutations:
        if not is_valid_graphql_name(mutation.name):
            # TODO: this does not warrant a popup, but it would be nice to show some kind of indication anyway
            log.error("Mutation with invalid GraphQL name detected: '%s'.", mutation.name)
            continue

        log.debug("Writing mutation '%s'.", mutation.name + '.graphql')
        filename = os.path.join(
            mutations_dir,
            "{}.graphql".format(mutation.name)
        )

        try:
            parsed = mutation.to_string(pad=4)
        except:
            raise Exception("Failed to parse mutation: '%s'!" % mutation.name)

        with open(filename, "w") as mutation_file:
            mutation_file.write(parsed)
