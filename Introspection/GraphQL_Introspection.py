#!/usr/bin/python

# Title: GraphQL Introspection
# Query a GraphQL endpoint with introspection in order to retrieve the documentation of all the Queries Mutations & Subscriptions
# Author: Paolo Stagno (@Void_Sec)
# Version: 1.6
# Added proxies by @deurstijl

import requests
import argparse
import sys
import time
import os
import json
from urlparse import urlparse
from datetime import date


RED = "\033[1;31;10m"
GREEN = "\033[1;32;10m"
YELLOW = "\033[1;37;10m"
WHITE = "\033[1;37;10m"
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
    # Introspection Query
    # -----------------------
    query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
    old_query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description args{...InputValue}onOperation onFragment onField}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"
    # -----------------------
    if key:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            "Authorization": key
            # TODO add the option for custom headers
        }
    else:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"
        }
    try:
        request = requests.post(target, json={"query": query}, headers=headers, proxies=proxyDict, verify=False)
        if request.status_code == 200:
            return request
        else:
            print "Trying the old introspection query"
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
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)


def main():
    parser = argparse.ArgumentParser(prog="GraphQL_Introspection.py", description="GraphQL Introspection")
    parser.add_argument("-t", dest="target", default=None,
                        help="Remote GraphQL Endpoint (https://<Target_IP>/graphql)")
    parser.add_argument("-f", dest="schema_json_file", default=None, help="Schema file in JSON format")
    parser.add_argument("-k", dest="key", help="API Authentication Key")    
    parser.add_argument("-c", dest="custom", action='store_true', default=False,
                        help="Add custom objects to the output (verbose)")
    parser.add_argument('-p', dest="proxy", default=None,
                        help='IP of web proxy to go through (http://127.0.0.1:8080)')


    args = parser.parse_args()

    if args.target is None and args.schema_json_file is None:
        print RED + "Remote GraphQL Endpoint OR a Schema file in JSON format must be specified!" + WHITE
        parser.print_help()
        sys.exit(1)

    if args.target is not None and args.schema_json_file is not None:
        print RED + "Only a Remote GraphQL Endpoint OR a Schema file in JSON format must be specified, not both!" + WHITE
        parser.print_help()
        sys.exit(1)       

    if args.proxy is not None:
    	proxyDict = { "http"  : args.proxy, "https" : args.proxy }
    else:
    	proxyDict = {}

    if args.target is not None or args.schema_json_file is not None :
        if args.target is not None :
            URL = urlparse(args.target).netloc
        else:
            URL = "localschema"
        timestamp = time.time()  # str(int(timestamp))
        today = str(date.today())
        # Create directory structure
        check_dir(URL + "/")

        with open(URL + "/doc-" + today + ".html", 'w') as output_file:
            if args.target is not None:
                result = query(args.target, args.key, proxyDict)
                # returns a dict
                result = result.json()
            else:
                with open(args.schema_json_file,"r") as s:
                    result_raw = s.read()
                    result = json.loads(result_raw)
            # Printing schema file
            schema_file = open(URL + "/schema-" + today + ".txt", "w")
            if args.target is not None:
                schema_file.write(json.dumps(result))  # return clean json
            else:
                schema_file.write(result_raw)
            schema_file.close()
            # --------------------
            output_file.write("<html><head><title>GraphQL Schema</title>")
            output_file.write(stl)
            output_file.write("</head><body><h2>GraphQL Schema</h2><h3><a href='{0}'>{0}</a></h3>".format(args.target))
            output_file.write(
                "<div class='box'><h4>Legend</h4><ul><li class='query'>Queries</li><li class='mutation'>Mutations</li><"
                "li class='subscription'>Subscriptions</li><li class='argument'>Arguments</li>"
                "<li class='type'>Types: String, Float, !not_null, [list]</li><li class='deprecated'>Deprecated</li>"
                "<li class='field'>Fields</li></ul></div>")
            output_file.write("<p>Available Operations Types:</p>")
            custom = args.custom
            try:
                # Print available operation types, usually: Query, Mutations & Subscriptions
                # This part also holds custom names (__schema[Type]['name'] != 'RootQuery', 'RootMutation' & 'Subscriptions')
                if result['data']['__schema']['mutationType'] is not None:
                    output_file.write("<ul><li class='mutation'>{0}</li>\n".format(
                        result['data']['__schema']['mutationType']['name']))
                    Mutation = result['data']['__schema']['mutationType']['name']
                if result['data']['__schema']['queryType']['name'] is not None:
                    output_file.write("<li class='query'>{0}</li>\n".format(
                        result['data']['__schema']['queryType']['name']))
                    Query = result['data']['__schema']['queryType']['name']
                if result['data']['__schema']['subscriptionType']['name'] is not None:
                    output_file.write(
                        "<li class='subscription'>{0}</li></ul>\n".format(
                            result['data']['__schema']['subscriptionType']['name']))
                    Subscription = result['data']['__schema']['subscriptionType']['name']
                ##########################################################################################
                i = 0
                # data
                #   __schema
                #       directives
                #       mutationType
                #       queryType
                #       subscriptionType
                #       types
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
                        k = 0
                        # Data -> Schema -> Types -> enumValues (name, description, isDeprecated, deprecationReason)
                        # TODO retieve enum values where present
                        if ((custom is False and (
                                rt[i]['enumValues'] is not None and (rt[i]['name'] not in primitives) and (
                                rt[i]['kind'] not in advanced_kind) and (
                                        (rt[i]['kind'] == "OBJECT") and (
                                        (rt[i]['name'] == Query) or (rt[i]['name'] == Mutation) or (
                                        rt[i]['name'] == Subscription))))) or (
                                custom is not False and ((rt[i]['enumValues'] is not None) and (
                                rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind)))):
                            for enumValues in rt[i]['enumValues']:
                                if rt[i]['enumValues'][k]['name'] is not None:
                                    output_file.write("<span>{0}</span>\n".format(rt[i]['enumValues'][k]['name']))
                                if rt[i]['enumValues'][k]['description'] is not None:
                                    output_file.write("<span class='description'>{0}</span>\n".format(
                                        rt[i]['enumValues'][k]['description']))
                                if rt[i]['enumValues'][k]['isDeprecated'] is not False and rt[i]['enumValues'][k][
                                    'isDeprecated'] is not None:
                                    output_file.write("<span class='deprecated'>Is Deprecated</span>\n")
                                if rt[i]['enumValues'][k]['deprecationReason'] is not None:
                                    output_file.write("<span>Reason: {0}</span>\n".format(
                                        rt[i]['enumValues'][k]['deprecationReason']))
                                k = k + 1
                        # Data -> Schema -> Types -> Fields (name, isDeprecated, deprecationReason, description)
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
                            for fields in result['data']['__schema']['types'][i]['fields']:
                                if rt[i]['fields'][j]['name'] is not None:
                                    if rt[i]['name'] == Query:
                                        output_file.write(
                                            "<li class='query'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                    elif rt[i]['name'] == Mutation:
                                        output_file.write(
                                            "<li class='mutation'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                    elif rt[i]['name'] == Subscription:
                                        output_file.write(
                                            "<li class='subscription'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                    elif rt[i]['kind'] == "OBJECT":
                                        output_file.write(
                                            "<li class='field'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                    else:
                                        output_file.write("<li>{0}</li>\n".format(rt[i]['fields'][j]['name']))
                                if rt[i]['fields'][j]['isDeprecated'] is not False and rt[i]['fields'][j][
                                    'isDeprecated'] is not None:
                                    output_file.write("<span class='deprecated'>Is Deprecated</span>\n")
                                if rt[i]['fields'][j]['deprecationReason'] is not None:
                                    output_file.write(
                                        "<span>Reason: {0}</span>\n".format(rt[i]['fields'][j]['deprecationReason']))
                                if rt[i]['fields'][j]['description'] is not None and rt[i]['fields'][j][
                                    'description'] != '':
                                    output_file.write(
                                        "<span class='description'>{0}</span>\n".format(
                                            rt[i]['fields'][j]['description']))
                                if rt[i]['fields'][j]['type'] is not None:
                                    if rt[i]['fields'][j]['type']['name'] is not None:
                                        output_file.write("<span class='type'>{0}</span>\n".format(
                                            rt[i]['fields'][j]['type']['name']))
                                if rt[i]['fields'][j]['type']['ofType'] is not None and \
                                        rt[i]['fields'][j]['type']['ofType']['name'] is not None:
                                    if rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type'][
                                        'kind'] == "LIST":
                                        output_file.write("<span class='type'>[{0}]</span>\n".format(
                                            rt[i]['fields'][j]['type']['ofType']['name']))
                                    elif rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type'][
                                        'kind'] == "NON_NULL":
                                        output_file.write("<span class='type'>!{0}</span>\n".format(
                                            rt[i]['fields'][j]['type']['ofType']['name']))
                                    else:
                                        output_file.write("<span class='type'>{0}</span>\n".format(
                                            rt[i]['fields'][j]['type']['ofType']['name']))
                                x = 0
                                if ((custom is False and ((rt[i]['fields'][j]['args'] is not None) and (
                                        rt[i]['name'] not in primitives) and (
                                                                  rt[i]['kind'] not in advanced_kind) and (
                                                                  (rt[i]['kind'] == "OBJECT") and (
                                                                  (rt[i]['name'] == Query) or (
                                                                  rt[i]['name'] == Mutation) or (
                                                                          rt[i]['name'] == Subscription))))) or (
                                        custom is not False and ((rt[i]['fields'][j]['args'] is not None) and (
                                        rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind)))):
                                    # Data -> Schema -> Types -> Fields -> Args (defaultValue, name, description)
                                    for args in rt[i]['fields'][j]['args']:
                                        if rt[i]['fields'][j]['args'][x]['defaultValue'] is not None:
                                            output_file.write(
                                                "<span>{0}</span>\n".format(
                                                    rt[i]['fields'][j]['args'][x]['defaultValue']))
                                        if rt[i]['fields'][j]['args'][x]['name'] is not None:
                                            output_file.write("<span class='argument'>{0}</span>\n".format(
                                                rt[i]['fields'][j]['args'][x]['name']))
                                        if rt[i]['fields'][j]['args'][x]['description'] is not None and \
                                                rt[i]['fields'][j]['args'][x]['description'] != '':
                                            output_file.write("<span class='description'>{0}</span>\n".format(
                                                rt[i]['fields'][j]['args'][x]['description']))
                                        # Data -> Schema -> Types -> Fields -> Args -> Type (name, ofType, kind)
                                        if rt[i]['fields'][j]['args'][x]['type'] is not None and (
                                                rt[i]['name'] not in primitives) and (
                                                rt[i]['kind'] not in advanced_kind):
                                            if rt[i]['fields'][j]['args'][x]['type']['kind'] == "LIST":
                                                output_file.write("<span class='type'>[{0}]</span>\n".format(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                            elif rt[i]['fields'][j]['args'][x]['type']['kind'] == "NON_NULL":
                                                output_file.write("<span class='type'>!{0}</span>\n".format(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                            else:
                                                if rt[i]['fields'][j]['args'][x]['type']['name'] is not None:
                                                    output_file.write("<span class='type'>{0}</span>\n".format(
                                                        rt[i]['fields'][j]['args'][x]['type']['name']))
                                                if rt[i]['fields'][j]['args'][x]['type']['ofType'] is not None:
                                                    output_file.write("<span>{0}</span>\n".format(
                                                        rt[i]['fields'][j]['args'][x]['type']['ofType']))
                                        x = x + 1
                                j = j + 1
                        i = i + 1
            # except KeyError:
            except Exception:
                raise
            output_file.write("</body></html>")
            output_file.close()
            print GREEN + "[DONE]" + WHITE
            sys.exit(0)
    else:
        print "Missing Arguments"
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print RED + "Exiting..." + WHITE
        sys.exit(1)
