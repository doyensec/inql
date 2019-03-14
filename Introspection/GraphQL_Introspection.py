#!/usr/bin/python

"""
Title: GraphQL Introspection
Author: Paolo Stagno (@Void_Sec) - https://voidsec.com
Version: 3.1
Query a GraphQL endpoint with introspection in order to retrieve the documentation of all the Queries, Mutations & Subscriptions.
The script will also generate Queries, Mutations & Subscriptions templates (with optional placeholders) for all the known types.
"""

import requests
import urllib3  # imported in order to suppress SSL warnings in main()
import argparse
import sys
import time
import os
import json
from urlparse import urlparse
from datetime import date

# colors for terminal messages
RED = "\033[1;31;10m[!] "
GREEN = "\033[1;32;10m[+] "
WHITE = "\033[1;37;10m"
YELLOW = "\033[1;33;10m[!] "

# CSS style used for the documentation
stl = """
<style>
body {
  font-family: Roboto;
  background-color: #f9f9f9;
}

li.query {
  color: #368cbf;
}

li.mutation {
  color: #30a;
}

li.subscription {
  color: #397D13;
}

li.argument {
  color: #edae49;
}

li.type {
  color: #7ebc59;
}

li.deprecated {
  color: red;
  ext-decoration: underline wavy red;
}

li.field {

}

li.description {
  color: grey;
}
span.query {
  color: #368cbf;
}

span.mutation {
  color: #30a;
}

span.subscription {
  color: #397D13;
}

span.argument {
  color: #edae49;
}

span.type {
  color: #7ebc59;
}

span.deprecated {
  color: red;
  ext-decoration: underline wavy red;
}

span.field {

}

span.description {
  color: grey;
}

div.box {
  background-color: white;
  width: 300px;
  border: 5px solid grey;
  padding: 10px;
  margin: 10px;
}
</style>
"""


def query(target, key, proxyDict):
    """
    Execute the introspection query against the GraphQL endpoint

    :param target:
        Expects a valid URL ex. https://example.com/graphql
        Raise an exception if HTTP/HTTPS schema is missing

    :param key:
        Optional parameter to be used as authentication header
        "Basic dXNlcjp0ZXN0"
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

    :param proxyDict:
        Optional parameter to be used as web proxy to go through
        ex. http://127.0.0.1:8080

    :return:
        Returns a dictionary objects to be parsed
    """
    # Introspection Query
    # -----------------------
    query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
    old_query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description args{...InputValue}onOperation onFragment onField}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"
    # -----------------------
    if key:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            "Authorization": key
            # TODO add the option for custom headers and variables
        }
    else:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"
        }
    try:
        # Issue the Introspection request against the GraphQL endpoint
        request = requests.post(target, json={"query": query}, headers=headers, proxies=proxyDict, verify=False)
        if request.status_code == 200:
            return request
        else:
            # if the returned HTTP code is not OK (200), will retry the Introspection query using the 'old' method
            print YELLOW + "Trying the old introspection query" + WHITE
            request = requests.post(target, json={"query": old_query}, headers=headers, proxies=proxyDict, verify=False)
            if request.status_code == 200:
                return request
            else:
                print RED + "Query failed! Code {}".format(request.status_code) + WHITE
                sys.exit(1)
    except requests.exceptions.MissingSchema:
        print RED + "Missing http:// or https:// schema from Target URL" + WHITE
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print RED + "Failed to establish a new connection: Connection refused" + WHITE
        sys.exit(1)


def check_dir(file_path):
    """
    Get a path as input, it will creates all the necessary (missing) directories in order to follow the provided path

    :param file_path:
        ex. /tmp/random/pizza
        it will create the directories random and pizza if not already present in the system

    :return:
        none
    """
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)


def file_write(URL, file_path, today, timestamp, file_name, content, mode):
    """
    This function is used in order to generate the Queries Mutations & Subscriptions templates.
    Path and file name will be generated as follow:

    :param URL:
        the target graphql endpoint stripped of its schema (HTTP/HTTPS)

    :param file_path:
        query, mutation, subscription

    :param today:
        date.today (2019-03-12)

    :param timestamp:
        timestamp

    :param file_name:
        query, mutation, subscription names

    :param content:
        file content

    :param mode:
        w, a and so on

    :return:
        none
    """
    write_file = open(URL + "/" + file_path + "/" + today + "/" + timestamp + "/" + file_name + ".txt", mode)
    write_file.write(content)


def detect_type(types):
    """
    This function will replace known GraphQL arguments types with placeholder values (useful for Burp Suite Repeater)

    :param types:
        Known types: String, Boolean, Float, Int, NOT_NULL
        TODO: add the support for custom objects and lists

    :return:
        Returns a placeholder accordingly to the provided type
    """
    # Switch between known args types
    if "String" in types:
        # needed fro Burp Repeater string handling
        types = '\\"' + types + '\\"'
        types = types.replace("String", "asd")
    elif "Boolean" in types:
        types = types.replace("Boolean", "TRUE")
    elif "Float" in types:
        types = types.replace("Float", "0.5")
    elif "Int" in types:
        types = types.replace("Int", "1")
    # strip the ! character (not null symbol) before returning the type
    types = types.replace("!", "")
    return types


def main():
    """
    Query a GraphQL endpoint with introspection in order to retrieve the documentation of all the Queries, Mutations & Subscriptions.
    It will also generate Queries, Mutations & Subscriptions templates (with optional placeholders) for all the known types.

    :return:
        none
    """
    # Args parser definition
    # -----------------------
    parser = argparse.ArgumentParser(prog="GraphQL_Introspection.py", description="GraphQL Introspection")
    parser.add_argument("-t", default=None, dest="target",
                        help="Remote GraphQL Endpoint (https://<Target_IP>/graphql)")
    parser.add_argument("-f", dest="schema_json_file", default=None, help="Schema file in JSON format")
    parser.add_argument("-k", dest="key", help="API Authentication Key")
    parser.add_argument('-p', dest="proxy", default=None,
                        help='IP of web proxy to go through (http://127.0.0.1:8080)')
    parser.add_argument("-d", dest="detect", action='store_true', default=False,
                        help="Replace known GraphQL arguments types with placeholder values (useful for Burp Suite)")
    parser.add_argument("-c", dest="custom", action='store_true', default=False,
                        help="Add custom objects to the output (verbose)")
    args = parser.parse_args()
    # -----------------------

    # At least one between -t or -f (target) parameters must be set
    if args.target is None and args.schema_json_file is None:
        print RED + "Remote GraphQL Endpoint OR a Schema file in JSON format must be specified!" + WHITE
        parser.print_help()
        sys.exit(1)

    # Only one of them -t OR -f :)
    if args.target is not None and args.schema_json_file is not None:
        print RED + "Only a Remote GraphQL Endpoint OR a Schema file in JSON format must be specified, not both!" + WHITE
        parser.print_help()
        sys.exit(1)

    # Takes care of any configured proxy (-p param)
    if args.proxy is not None:
        print YELLOW + "Proxy ENABLED: " + args.proxy + WHITE
        proxyDict = {"http": args.proxy, "https": args.proxy}
    else:
        proxyDict = {}

    if args.target is not None or args.schema_json_file is not None:
        if args.target is not None:
            # Acquire GraphQL endpoint URL as a target
            URL = urlparse(args.target).netloc
        else:
            # Acquire a local JSON file as a target
            print YELLOW + "Parsing local schema file" + WHITE
            URL = "localschema"
        detect = args.detect
        if detect:
            print YELLOW + "Detect arguments is ENABLED, known types will be replaced with placeholder values" + WHITE
        if args.custom:
            print YELLOW + "Custom objects is ENABLED, output documentation will be very verbose" + WHITE
        # Used to generate 'unique' file names for multiple documentation
        timestamp = time.time()  # Can be printed with: str(int(timestamp))
        today = str(date.today())
        # Create directories structure
        # -----------------------
        check_dir(URL + "/query/" + today + "/" + str(int(timestamp)) + "/")
        check_dir(URL + "/mutation/" + today + "/" + str(int(timestamp)) + "/")
        check_dir(URL + "/subscription/" + today + "/" + str(int(timestamp)) + "/")
        # -----------------------
        # Setup lists for templates generation
        # -----------------------
        args_type = []
        q_name = []
        q_args_name = []
        m_name = []
        m_args_name = []
        s_name = []
        s_args_name = []
        # -----------------------

        # Generate the documentation for the target
        with open(URL + "/doc-" + today + "-" + str(int(timestamp)) + ".html", 'w') as output_file:
            if args.target is not None:
                # Parse response from the GraphQL endpoint
                result = query(args.target, args.key, proxyDict)
                # returns a dict
                result = result.json()
            else:
                # Parse the local JSON file
                with open(args.schema_json_file, "r") as s:
                    result_raw = s.read()
                    result = json.loads(result_raw)
            # Write schema file
            schema_file = open(URL + "/schema-" + today + "-" + str(int(timestamp)) + ".txt", "w")
            if args.target is not None:
                # returns a prettified json
                schema_file.write(json.dumps(result))
            else:
                schema_file.write(result_raw)
            schema_file.close()
            # Write HTML header for the documentation
            # --------------------
            output_file.write("<html><head><title>GraphQL Schema</title>")
            # write CSS
            output_file.write(stl)
            # write target URL
            output_file.write("</head><body><h2>GraphQL Schema</h2><h3><a href='{0}'>{0}</a></h3>".format(args.target))
            # write legend box
            output_file.write(
                "<div class='box'><h4>Legend</h4><ul><li class='query'>Queries</li><li class='mutation'>Mutations</li><"
                "li class='subscription'>Subscriptions</li><li class='argument'>Arguments</li>"
                "<li class='type'>Types: String, Float, !not_null, [list]</li><li class='deprecated'>Deprecated</li>"
                "<li class='field'>Fields</li></ul></div>")
            # --------------------
            output_file.write("<p>Available Operations Types:</p>")
            custom = args.custom
            try:
                # Print available operation types, usually: Query, Mutations & Subscriptions
                # This part also holds custom names (schema[Type]['name'] != 'RootQuery', 'RootMutation', 'Subscriptions')
                # --------------------
                if result['data']['__schema']['mutationType'] is not None:
                    output_file.write("<ul><li class='mutation'>{0}</li>\n".format(
                        result['data']['__schema']['mutationType']['name']))
                    Mutation = result['data']['__schema']['mutationType']['name']
                else:
                    # Needed since not all GraphQL endpoints use/have all the three types (Query, Mutations & Subscriptions)
                    Mutation = None
                if result['data']['__schema']['queryType'] is not None:
                    output_file.write("<li class='query'>{0}</li>\n".format(
                        result['data']['__schema']['queryType']['name']))
                    Query = result['data']['__schema']['queryType']['name']
                else:
                    Query = None
                if result['data']['__schema']['subscriptionType'] is not None:
                    output_file.write(
                        "<li class='subscription'>{0}</li></ul>\n".format(
                            result['data']['__schema']['subscriptionType']['name']))
                    Subscription = result['data']['__schema']['subscriptionType']['name']
                else:
                    Subscription = None
                # --------------------
                i = 0
                ##########################################################################################
                # Parsing JSON response/file structure as follows
                # data
                #   __schema
                #       directives
                #       mutationType
                #       queryType
                #       subscriptionType
                #       types
                #              name (RootQuery, RootMutation, Subscriptions)
                #              fields
                #                     name (nome query)
                #                     args
                #                            name (arg name)
                #                            type
                #                                   name (type arg)
                ##########################################################################################
                # Start looping trough types
                if result['data']['__schema']['types'] is not None:
                    rt = result['data']['__schema']['types']
                    for types in rt:
                        j = 0
                        # Data -> Schema -> Types (kind, name, description)
                        # filtering out kind == SCALAR & name != primitive types
                        # TODO: exclude interfaces & union types
                        primitives = ['Int', 'Float', 'String', 'Boolean', 'ID', '__TypeKind', '__Type', '__Schema',
                                      '__Field', '__InputValue', '__EnumValue', '__Directive', '__DirectiveLocation']
                        advanced_kind = ['INPUT_OBJECT']
                        if ((custom is False and ((rt[i]['kind'] is not None and rt[i]['name'] is not None) and (
                                rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind) and (
                                                          (rt[i]['kind'] == "OBJECT") and (
                                                          (rt[i]['name'] == Query) or (rt[i]['name'] == Mutation) or (
                                                          rt[i]['name'] == Subscription))))) or (
                                custom is not False and ((rt[i]['kind'] is not None and rt[i]['name'] is not None) and (
                                rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind)))):
                            output_file.write("<li>{0}</li>\n".format(rt[i]['kind']))
                            # Print our types RootQuery, RootMutation, Subscriptions
                            # --------------------
                            if rt[i]['name'] == Mutation:
                                output_file.write("<li class='mutation'>{0}</li>\n".format(rt[i]['name']))
                            elif rt[i]['name'] == Query:
                                output_file.write("<li class='query'>{0}</li>\n".format(rt[i]['name']))
                            elif rt[i]['name'] == Subscription:
                                output_file.write("<li class='subscription'>{0}</li>\n".format(rt[i]['name']))
                            else:
                                if rt[i]['description'] is not None:
                                    output_file.write(
                                        "<span class='description'>{0}</span>\n".format(rt[i]['description']))
                                output_file.write("<span class='type'>{0}</span>\n".format(rt[i]['name']))
                            # --------------------
                        k = 0
                        # Retrieving general docs (I honestly do not remember what kind of info are being extracted here, maybe custom types have them)
                        # Data -> Schema -> Types -> enumValues (name, description, isDeprecated, deprecationReason)
                        # My super BOOLEAN IF, used to switch between ENABLED custom types parameter (-c)
                        if ((custom is False and (
                                rt[i]['enumValues'] is not None and (rt[i]['name'] not in primitives) and (
                                rt[i]['kind'] not in advanced_kind) and (
                                        (rt[i]['kind'] == "OBJECT") and (
                                        (rt[i]['name'] == Query) or (rt[i]['name'] == Mutation) or (
                                        rt[i]['name'] == Subscription))))) or (
                                custom is not False and ((rt[i]['enumValues'] is not None) and (
                                rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind)))):
                            for enumValues in rt[i]['enumValues']:
                                # Name
                                if rt[i]['enumValues'][k]['name'] is not None:
                                    output_file.write("<span>{0}</span>\n".format(rt[i]['enumValues'][k]['name']))
                                # Description
                                if rt[i]['enumValues'][k]['description'] is not None:
                                    output_file.write("<span class='description'>{0}</span>\n".format(
                                        rt[i]['enumValues'][k]['description']))
                                # Is Deprecated?
                                if rt[i]['enumValues'][k]['isDeprecated'] is not False and rt[i]['enumValues'][k][
                                    'isDeprecated'] is not None:
                                    output_file.write("<span class='deprecated'>Is Deprecated</span>\n")
                                # Deprecation Reason
                                if rt[i]['enumValues'][k]['deprecationReason'] is not None:
                                    output_file.write("<span>Reason: {0}</span>\n".format(
                                        rt[i]['enumValues'][k]['deprecationReason']))
                                k = k + 1
                        # Retrieving queries, mutations and subscriptions information
                        # Data -> Schema -> Types -> Fields (name, isDeprecated, deprecationReason, description)
                        # This super if is BOOLEAN able to switch between ENABLED custom types parameter (-c)
                        # It will selectively routine trough values needed to print
                        if ((custom is False and ((
                                                          rt[i]['fields'] is not None) and (
                                                          rt[i]['name'] not in primitives) and (
                                                          rt[i]['kind'] not in advanced_kind) and (
                                                          (rt[i]['kind'] == "OBJECT") and (
                                                          (rt[i]['name'] == Query) or (rt[i]['name'] == Mutation) or (
                                                          rt[i]['name'] == Subscription))))) or (
                                custom is not False and ((
                                                                 rt[i]['fields'] is not None) and (
                                                                 rt[i]['name'] not in primitives) and (
                                                                 rt[i]['kind'] not in advanced_kind)))):
                            # Printing out queries, mutations and subscriptions names
                            # --------------------
                            for fields in result['data']['__schema']['types'][i]['fields']:
                                if rt[i]['fields'][j]['name'] is not None:
                                    # Query
                                    if rt[i]['name'] == Query:
                                        output_file.write(
                                            "<li class='query'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                        q_name.append(rt[i]['fields'][j]['name'])
                                    # Mutation
                                    elif rt[i]['name'] == Mutation:
                                        output_file.write(
                                            "<li class='mutation'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                        m_name.append(rt[i]['fields'][j]['name'])
                                    # Subscription
                                    elif rt[i]['name'] == Subscription:
                                        output_file.write(
                                            "<li class='subscription'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                        s_name.append(rt[i]['fields'][j]['name'])
                                    # Root objects or custom ones
                                    elif rt[i]['kind'] == "OBJECT":
                                        output_file.write(
                                            "<li class='field'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                    else:
                                        output_file.write("<li>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                # --------------------
                                # Printing info regarding the queries, mutations and subscriptions above
                                # --------------------
                                # Deprecated
                                if rt[i]['fields'][j]['isDeprecated'] is not False and rt[i]['fields'][j][
                                    'isDeprecated'] is not None:
                                    output_file.write("<span class='deprecated'>Is Deprecated</span>\n")
                                # Deprecated Reason
                                if rt[i]['fields'][j]['deprecationReason'] is not None:
                                    output_file.write(
                                        "<span>Reason: {0}</span>\n".format(rt[i]['fields'][j]['deprecationReason']))
                                # Description
                                if rt[i]['fields'][j]['description'] is not None and rt[i]['fields'][j][
                                    'description'] != '':
                                    output_file.write(
                                        "<span class='description'>{0}</span>\n".format(
                                            rt[i]['fields'][j]['description']))
                                # Name
                                if rt[i]['fields'][j]['type'] is not None:
                                    if rt[i]['fields'][j]['type']['name'] is not None:
                                        output_file.write("<span class='type'>{0}</span>\n".format(
                                            rt[i]['fields'][j]['type']['name']))
                                # Type
                                if rt[i]['fields'][j]['type']['ofType'] is not None and \
                                        rt[i]['fields'][j]['type']['ofType']['name'] is not None:
                                    # LIST
                                    if rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type'][
                                        'kind'] == "LIST":
                                        output_file.write("<span class='type'>[{0}]</span>\n".format(
                                            rt[i]['fields'][j]['type']['ofType']['name']))
                                    # NOT NULL
                                    elif rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type'][
                                        'kind'] == "NON_NULL":
                                        output_file.write("<span class='type'>!{0}</span>\n".format(
                                            rt[i]['fields'][j]['type']['ofType']['name']))
                                    # CUSTOM TYPE
                                    else:
                                        output_file.write("<span class='type'>{0}</span>\n".format(
                                            rt[i]['fields'][j]['type']['ofType']['name']))
                                # --------------------
                                x = 0
                                # Prepare a list of ARGS names for queries, mutations and subscriptions
                                # --------------------
                                if not rt[i]['fields'][j]['args']:
                                    if rt[i]['name'] == Query:
                                        q_args_name.append([])
                                        q_args_name[j].append("")
                                    elif rt[i]['name'] == Mutation:
                                        m_args_name.append([])
                                        m_args_name[j].append("")
                                    elif rt[i]['name'] == Subscription:
                                        s_args_name.append([])
                                        s_args_name[j].append("")
                                    args_type.append("")
                                # --------------------
                                # Again, super if BOOLEAN based for custom types parameters (-c)
                                if ((custom is False and ((rt[i]['fields'][j]['args'] is not None) and (
                                        rt[i]['name'] not in primitives) and (
                                                                  rt[i]['kind'] not in advanced_kind) and (
                                                                  (rt[i]['kind'] == "OBJECT") and (
                                                                  (rt[i]['name'] == Query) or (
                                                                  rt[i]['name'] == Mutation) or (
                                                                          rt[i]['name'] == Subscription))))) or (
                                        custom is not False and ((rt[i]['fields'][j]['args'] is not None) and (
                                        rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind)))):
                                    # Printing out queries, mutations and subscriptions ARGS name
                                    # Data -> Schema -> Types -> Fields -> Args (defaultValue, name, description)
                                    # --------------------
                                    for args in rt[i]['fields'][j]['args']:
                                        # Default value if present
                                        if rt[i]['fields'][j]['args'][x]['defaultValue'] is not None:
                                            output_file.write(
                                                "<span>{0}</span>\n".format(
                                                    rt[i]['fields'][j]['args'][x]['defaultValue']))
                                        # ARGS name
                                        if rt[i]['fields'][j]['args'][x]['name'] is not None:
                                            output_file.write("<span class='argument'>{0}</span>\n".format(
                                                rt[i]['fields'][j]['args'][x]['name']))
                                            # Will append the ARG name to the correct list
                                            # based on if it is an argument from query, mutation or subscription
                                            # --------------------
                                            if rt[i]['name'] == Query:
                                                q_args_name.append([])
                                                q_args_name[j].append(rt[i]['fields'][j]['args'][x]['name'])
                                            elif rt[i]['name'] == Mutation:
                                                m_args_name.append([])
                                                m_args_name[j].append(rt[i]['fields'][j]['args'][x]['name'])
                                            elif rt[i]['name'] == Subscription:
                                                s_args_name.append([])
                                                s_args_name[j].append(rt[i]['fields'][j]['args'][x]['name'])
                                            # --------------------
                                        # ARGS description
                                        if rt[i]['fields'][j]['args'][x]['description'] is not None and \
                                                rt[i]['fields'][j]['args'][x]['description'] != '':
                                            output_file.write("<span class='description'>{0}</span>\n".format(
                                                rt[i]['fields'][j]['args'][x]['description']))
                                    # --------------------
                                        # Printing out ARGS types
                                        # Data -> Schema -> Types -> Fields -> Args -> Type (name, ofType, kind)
                                        # --------------------
                                        if rt[i]['fields'][j]['args'][x]['type'] is not None and (
                                                rt[i]['name'] not in primitives) and (
                                                rt[i]['kind'] not in advanced_kind):
                                            # LIST
                                            if rt[i]['fields'][j]['args'][x]['type']['kind'] == "LIST":
                                                output_file.write("<span class='type'>[{0}]</span>\n".format(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                                args_type.append(
                                                    "[" + rt[i]['fields'][j]['args'][x]['type']['ofType']['name'] + "]")
                                            # NOT NULL
                                            elif rt[i]['fields'][j]['args'][x]['type']['kind'] == "NON_NULL":
                                                output_file.write("<span class='type'>!{0}</span>\n".format(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                                args_type.append(
                                                    "!" + rt[i]['fields'][j]['args'][x]['type']['ofType']['name'])
                                            # CUSTOM TYPE
                                            else:
                                                if rt[i]['fields'][j]['args'][x]['type']['name'] is not None:
                                                    output_file.write("<span class='type'>{0}</span>\n".format(
                                                        rt[i]['fields'][j]['args'][x]['type']['name']))
                                                    args_type.append(rt[i]['fields'][j]['args'][x]['type']['name'])
                                                if rt[i]['fields'][j]['args'][x]['type']['ofType'] is not None:
                                                    output_file.write("<span>{0}</span>\n".format(
                                                        rt[i]['fields'][j]['args'][x]['type']['ofType']))
                                        # --------------------
                                        x += 1
                                j += 1
                        i += 1
            # Used for None key exceptions: except KeyError:
            except Exception:
                raise
            # Close documentation
            output_file.write("</body></html>")
            output_file.close()
            # Writing templates
            # Reverse args list in order to use pop
            args_type.reverse()
            # --------------------
            # QUERY
            # --------------------
            print WHITE + "[-] Writing Queries Templates" + WHITE
            index = 0
            for qname in q_name:
                file_write(URL, "query", today, str(int(timestamp)), qname, "{\"query\":\"query{" + qname + "(", "w")
                for argsname in q_args_name[index]:
                    # POP out of the list empty values
                    if argsname != "":
                        # if detect type (-d param) is enabled, retrieve placeholders according to arg type
                        if detect:
                            file_write(URL, "query", today, str(int(timestamp)), qname, argsname + ":" + detect_type(args_type.pop()) + " ", "a")
                        else:
                            file_write(URL, "query", today, str(int(timestamp)), qname, argsname + ":" + args_type.pop() + " ", "a")
                    else:
                        args_type.pop()
                # Query name
                file_write(URL, "query", today, str(int(timestamp)), qname, "){", "a")
                # Query args
                for argsname in q_args_name[index]:
                    file_write(URL, "query", today, str(int(timestamp)), qname, argsname + " ", "a")
                # Close query
                file_write(URL, "query", today, str(int(timestamp)), qname, "}}\"}", "a")
                index += 1
            # --------------------
            # MUTATION
            # --------------------
            print WHITE + "[-] Writing Mutations Templates" + WHITE
            index = 0
            for mname in m_name:
                file_write(URL, "mutation", today, str(int(timestamp)), mname, "{\"mutation\":\"mutation{" + mname + "(", "w")
                for argsname in m_args_name[index]:
                    # POP out of the list empty values
                    if argsname != "":
                        # if detect type (-d param) is enabled, retrieve placeholders according to arg type
                        if detect:
                            file_write(URL, "mutation", today, str(int(timestamp)), mname, argsname + ":" + detect_type(args_type.pop()) + " ", "a")
                        else:
                            file_write(URL, "mutation", today, str(int(timestamp)), mname, argsname + ":" + args_type.pop() + " ", "a")
                    else:
                        args_type.pop()
                # Mutation name
                file_write(URL, "mutation", today, str(int(timestamp)), mname, "){", "a")
                # Mutation args
                for argsname in m_args_name[index]:
                    file_write(URL, "mutation", today, str(int(timestamp)), mname, argsname + " ", "a")
                # Close mutation
                file_write(URL, "mutation", today, str(int(timestamp)), mname, "}}\"}", "a")
                index += 1
            # --------------------
            # SUBSCRIPTION
            # --------------------
            print WHITE + "[-] Writing Subscriptions Templates" + WHITE
            index = 0
            for sname in s_name:
                file_write(URL, "subscription", today, str(int(timestamp)), sname, "{\"subscription\":\"subscription{{" + sname + "(", "w")
                for argsname in s_args_name[index]:
                    # POP out of the list empty values
                    if argsname != "":
                        # if detect type (-d param) is enabled, retrieve placeholders according to arg type
                        if detect:
                            file_write(URL, "subscription", today, str(int(timestamp)), sname, argsname + ":" + detect_type(args_type.pop()) + " ", "a")
                        else:
                            file_write(URL, "subscription", today, str(int(timestamp)), sname, argsname + ":" + args_type.pop() + " ", "a")
                    else:
                        args_type.pop()
                # Subscription name
                file_write(URL, "subscription", today, str(int(timestamp)), sname, "){", "a")
                # Subscription args
                for argsname in s_args_name[index]:
                    file_write(URL, "subscription", today, str(int(timestamp)), sname, argsname + " ", "a")
                # Close subscription
                file_write(URL, "subscription", today, str(int(timestamp)), sname, "}}\"}", "a")
                index += 1
            # --------------------
            # THE END, they all lived happily ever after (hopefully)
            print GREEN + "DONE" + WHITE
            sys.exit(0)
    else:
        # Likely missing a required arguments
        print "Missing Arguments"
        parser.print_help()


if __name__ == "__main__":
    try:
        # Suppress SSL Warning due to unverified HTTPS requests.
        # See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        main()
    except KeyboardInterrupt:
        # Catch CTRL+C, it will abruptly kill the script
        print RED + "Exiting..." + WHITE
        sys.exit(1)
