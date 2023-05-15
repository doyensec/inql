# coding: utf-8
import json
import os
from collections import OrderedDict
from datetime import datetime
from urlparse import urlparse

from java.awt import Cursor
from java.lang import RuntimeException

from gqlspection import GQLSchema
from gqlspection.utils import query_introspection

from ..config import config, enabled_categories
from ..globals import app
from ..logger import log
from ..utils.decorators import threaded
from ..utils.graphql import is_valid_graphql_name
from ..utils.http import Request
from ..utils.ui import visual_error


# TODO: Support four additional content-type options:
#   1. GET requests
#   2. application/graphql
#   3. urlencoded POST
#   4. form-data POST
def _normalize_headers(host, explicit_headers):
    """Make sure headers contain valid host and content type.

    If no content type is provided, default to application/json.
    Explicit headers should be a dict. _normalize_headers will return a dict as well.
    """
    explicit_headers = explicit_headers or {}

    headers = OrderedDict()

    # Host header is required, and must be the first header
    if 'Host' in explicit_headers:
        headers['Host'] = explicit_headers['Host']
        del explicit_headers['Host']
    else:
        headers['Host'] = host

    content_type_present = False
    for k, v in explicit_headers:
        log.debug("Custom header: %s: %s", k, v)
        headers[k] = v

        if (k.lower() == 'content-type' and
            v.lower() in ('application/json', 'application/graphql')):
            content_type_present = True

    if not content_type_present:
        headers['Content-Type'] = 'application/json'

    log.debug("Normalized headers: %s", headers)
    return headers


@threaded
def analyze(url, filename=None, headers=None):
    """
    Analyze the introspection JSON and populate GUI with results (runs async in a new thread!).

    'url' must be provided, schema_filename could be None.
    """
    try:
        app.omnibar.set_busy(True)
        _analyze(url, filename, headers)
        app.omnibar.file = ''
    except Exception as e:
        app.omnibar.file = filename
        visual_error(str(e))
    finally:
        app.fileview.refresh()
        app.omnibar.set_busy(False)


# TODO: The exception handling here is all over the place. Improvements are welcome.
# TODO: Would be nice to process as much as possible, instead of failing at first exception.
def _analyze(url, filename=None, explicit_headers=None):
    host = urlparse(url).netloc
    headers = _normalize_headers(host, explicit_headers)
    log.debug("Headers: %s", headers)

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
        # Build the request template by initializing query_introspection with a mocked request
        try:
            request = Request(mock=True)
            query_introspection(url, headers, request_fn=request)
        except:
            # Expected to fail, always
            pass
    else:
        log.debug("GraphQL schema will be queried from the server.")
        try:
            request = Request()
            schema = query_introspection(url, headers, request_fn=request)
        except Exception as e:
            # TODO: show some visual feedback here as well
            log.error("No JSON schema provided and server '%s' did not return results for the introspection query (exception: %s).", host, e)
            raise Exception("Introspection schema does not seem to be enabled on the server! Provide schema as a JSON file.")
        except RuntimeException as e:
            log.error(e)
            raise Exception("Domain does not exist.")

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

    with open(os.path.join(report_dir, "request_template.txt"), "wb") as f:
        log.debug("Dumping the request template.")
        f.write(url + '\n')
        f.write(request.template)

    # Dump JSON schema
    if config.get('report.introspection'):
        with open(os.path.join(report_dir, "schema.json"), "w") as schema_file:
            log.debug("Dumping JSON schema")
            schema_file.write(json.dumps(schema, indent=4, sort_keys=True))

    log.debug("About to parse the schema received from '%s'.", url)
    try:
        parsed_schema = GQLSchema(json=schema)
    except:
        log.error("Could not parse the received GraphQL schema.")
        raise Exception("Could not parse the received GraphQL schema. Validate dumped JSON manually and file a bug report if it seems correct.")

    # Write query files
    log.debug("Writing queries for the url: '%s'.", url)
    for query in parsed_schema.query.fields:
        if not query.name:
            log.error("Query without a name detected.")
            continue

        if not is_valid_graphql_name(query.name):
            log.error("Query with invalid GraphQL name detected: '%s'.", query.name)
            continue

        filename = os.path.join(
            queries_dir,
            "{}.graphql".format(query.name)
        )

        log.debug("Writing query " + query.name + '.graphql to ' + filename)
        with open(filename, "w") as query_file:
            query_file.write(
                parsed_schema.generate_query(query, depth=config.get('codegen.depth'))
                .to_string(pad=config.get('codegen.pad')))
        log.debug("Wrote query '%s'.", query.name + '.graphql')

    # Write mutations, if any
    if parsed_schema.mutation is None:
        log.debug("No mutations found for the url: '%s'.", url)
    else:
        log.debug("Writing mutations for the url: '%s'.", url)
        for mutation in parsed_schema.mutation.fields:
            if not mutation.name:
                log.error("Mutation without a name detected.")
                continue

            if not is_valid_graphql_name(mutation.name):
                log.error("Mutation with invalid GraphQL name detected: '%s'.", mutation.name)
                continue

            filename = os.path.join(
                mutations_dir,
                "{}.graphql".format(mutation.name)
            )

            log.debug("Writing mutation " + mutation.name + '.graphql to ' + filename)
            with open(filename, "w") as mutation_file:
                mutation_file.write(
                    parsed_schema.generate_mutation(mutation, depth=config.get('codegen.depth'))
                    .to_string(pad=config.get('codegen.pad')))
            log.debug("Wrote mutation '%s'.", mutation.name + '.graphql')

    # Write the 'Points of Interest' report
    if config.get('report.poi'):
        log.debug("Writing the 'Points of Interest' report for the url: '%s'.", url)

        # Get the points of interest (JSON)
        poi_json = parsed_schema.points_of_interest(
            depth=config.get('report.poi.depth'),
            categories=enabled_categories(),
            keywords=config.get('report.poi.custom_keywords').split('\n')
        )

        format = config.get('report.poi.format')

        # Write the points of interest (JSON)
        if format == 'json' or format == 'both':
            with open(os.path.join(report_dir, "poi.json"), "w") as poi_file:
                json.dump(poi_json, poi_file, indent=4, sort_keys=True)

        if format == 'text' or format == 'both':
            # Write the points of interest (text)
            with open(os.path.join(report_dir, "poi.txt"), "w") as poi_file:
                poi_file.write(parsed_schema._parse_points_of_interest(poi_json))
