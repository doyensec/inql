from inql.utils import open


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


def generate(argument, fpath, custom=False, target="empty"):
    with open(fpath, 'w') as output_file:
        result = argument.copy()
        # Write HTML header for the documentation
        # --------------------
        output_file.write("<html><head><title>GraphQL Schema</title>")
        # write CSS
        output_file.write(stl)
        # write target URL
        output_file.write("</head><body><h2>GraphQL Schema</h2><h3><a href='{0}'>{0}</a></h3>".format(target))
        # write legend box
        output_file.write(
            "<div class='box'><h4>Legend</h4><ul><li class='query'>Queries</li><li class='mutation'>Mutations</li><"
            "li class='subscription'>Subscriptions</li><li class='argument'>Arguments</li>"
            "<li class='type'>Types: String, Float, not_null!, [list]</li><li class='deprecated'>Deprecated</li>"
            "<li class='field'>Fields</li></ul></div>")
        # --------------------
        output_file.write("<p>Available Operations Types:</p>")
        try:
            # Print available operation types, usually: Query, Mutations & Subscriptions
            # This part also holds custom names (schema[Type]['name'] != 'RootQuery', 'RootMutation', 'Subscriptions')
            # --------------------
            if result['data']['__schema']['mutationType'] is not None:
                output_file.write("<ul><li class='mutation'>{0}</li>".format(
                    result['data']['__schema']['mutationType']['name']))
                Mutation = result['data']['__schema']['mutationType']['name']
            else:
                # Needed since not all GraphQL endpoints use/have all the three types (Query, Mutations & Subscriptions)
                Mutation = None
            if result['data']['__schema']['queryType'] is not None:
                output_file.write("<li class='query'>{0}</li>".format(
                    result['data']['__schema']['queryType']['name']))
                Query = result['data']['__schema']['queryType']['name']
            else:
                Query = None
            if result['data']['__schema']['subscriptionType'] is not None:
                output_file.write(
                    "<li class='subscription'>{0}</li></ul>".format(
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
            #       types (kind, name, description)
            #              name (RootQuery, RootMutation, Subscriptions, [custom] OBJECT)
            #              fields
            #                     name (query names)
            #                     args
            #                            name (args names)
            #                            type
            #                                   name (args types)
            ##########################################################################################
            # Start looping trough types
            if result['data']['__schema']['types'] is not None:
                rt = result['data']['__schema']['types']
                # holds the number of custom objects
                xxx = 0
                for types in rt:
                    j = 0
                    # Data -> Schema -> Types (kind, name, description)
                    # filtering out primitive types
                    # TODO: exclude interfaces & union types
                    primitives = ['Int', 'Float', 'String', 'Boolean', 'ID', '__TypeKind', '__Type', '__Schema',
                                  '__Field', '__InputValue', '__EnumValue', '__Directive', '__DirectiveLocation']
                    advanced_kind = ['INPUT_OBJECT']
                    # This super if is BOOLEAN able to switch between ENABLED custom types parameter (-c)
                    # It will selectively routine trough values needed to print
                    if ((custom is False and ((rt[i]['kind'] is not None and rt[i]['name'] is not None) and (
                            rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind) and (
                                                      (rt[i]['kind'] == "OBJECT") and (
                                                      (rt[i]['name'] == Query) or (rt[i]['name'] == Mutation) or (
                                                      rt[i]['name'] == Subscription))))) or (
                            custom is not False and ((rt[i]['kind'] is not None and rt[i]['name'] is not None) and (
                            rt[i]['name'] not in primitives) and (rt[i]['kind'] not in advanced_kind)))):
                        output_file.write("<li>{0}</li>".format(rt[i]['kind']))
                        # Print our types RootQuery, RootMutation, Subscriptions
                        # --------------------
                        if rt[i]['name'] == Mutation:
                            output_file.write("<li class='mutation'>{0}</li>".format(rt[i]['name']))
                        elif rt[i]['name'] == Query:
                            output_file.write("<li class='query'>{0}</li>".format(rt[i]['name']))
                        elif rt[i]['name'] == Subscription:
                            output_file.write("<li class='subscription'>{0}</li>".format(rt[i]['name']))
                        # Handles custom objects (FIELDS)
                        elif rt[i]['kind'] == "OBJECT" and rt[i]['name'] is not None:
                            output_file.write("<span class='type'>{0}</span><br>".format(rt[i]['name']))
                            xxx += 1
                        if rt[i]['description'] is not None:
                            output_file.write(
                                "<span class='description'>{0}</span><br>".format(rt[i]['description']))
                        # --------------------
                    k = 0
                    # Retrieving general docs regarding primitives (filtered out from documentation, not needed)
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
                                output_file.write("<span>{0}</span><br>".format(rt[i]['enumValues'][k]['name']))
                            # Description
                            if rt[i]['enumValues'][k]['description'] is not None:
                                output_file.write("<span class='description'>{0}</span><br>".format(
                                    rt[i]['enumValues'][k]['description']))
                            # Is Deprecated?
                            if rt[i]['enumValues'][k]['isDeprecated'] is not False and rt[i]['enumValues'][k][
                                'isDeprecated'] is not None:
                                output_file.write("<span class='deprecated'>Is Deprecated</span><br>")
                            # Deprecation Reason
                            if rt[i]['enumValues'][k]['deprecationReason'] is not None:
                                output_file.write("<span>Reason: {0}</span><br>".format(
                                    rt[i]['enumValues'][k]['deprecationReason']))
                            k = k + 1
                    # Retrieving queries, mutations and subscriptions information
                    # Data -> Schema -> Types -> Fields (name, isDeprecated, deprecationReason, description)
                    # My super BOOLEAN IF, used to switch between ENABLED custom types parameter (-c)
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
                        # Printing out queries, mutations, subscriptions and custom object names
                        # --------------------
                        # number of fields per obj
                        for fields in result['data']['__schema']['types'][i]['fields']:
                            if rt[i]['fields'][j]['name'] is not None:
                                # Query
                                if rt[i]['name'] == Query:
                                    output_file.write(
                                        "<li class='query'>{0}</li>".format(rt[i]['fields'][j]['name']))
                                # Mutation
                                elif rt[i]['name'] == Mutation:
                                    output_file.write(
                                        "<li class='mutation'>{0}</li>".format(rt[i]['fields'][j]['name']))
                                # Subscription
                                elif rt[i]['name'] == Subscription:
                                    output_file.write(
                                        "<li class='subscription'>{0}</li>".format(rt[i]['fields'][j]['name']))
                                # It handle custom objects
                                elif rt[i]['kind'] == "OBJECT":
                                    output_file.write(
                                        "<span class='field'>{0}</span>&nbsp;&nbsp;".format(
                                            rt[i]['fields'][j]['name']))
                                # Seems that i do not need the following two lines
                                # else:
                                #    output_file.write("<li>{0}</li>".format(rt[i]['fields'][j]['name']))
                            # --------------------
                            # Printing info regarding the queries, mutations and subscriptions above
                            # --------------------
                            # Deprecated
                            if rt[i]['fields'][j]['isDeprecated'] is not False and rt[i]['fields'][j][
                                'isDeprecated'] is not None:
                                output_file.write("<span class='deprecated'>Is Deprecated</span><br>")
                            # Deprecated Reason
                            if rt[i]['fields'][j]['deprecationReason'] is not None:
                                output_file.write(
                                    "<span>Reason: {0}</span><br>".format(rt[i]['fields'][j]['deprecationReason']))
                            # Description
                            if rt[i]['fields'][j]['description'] is not None and rt[i]['fields'][j][
                                'description'] != '':
                                output_file.write(
                                    "<span class='description'>{0}</span><br>".format(
                                        rt[i]['fields'][j]['description']))
                            # Name (fields type)
                            if rt[i]['fields'][j]['type'] is not None:
                                if rt[i]['fields'][j]['type']['name'] is not None:
                                    output_file.write("<span class='type'>{0}</span><br>".format(
                                        rt[i]['fields'][j]['type']['name']))
                            # oFType
                            if rt[i]['fields'][j]['type']['ofType'] is not None and \
                                    rt[i]['fields'][j]['type']['ofType']['name'] is not None:
                                # LIST
                                if rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type'][
                                    'kind'] == "LIST":
                                    output_file.write("<span class='type'>[{0}]</span><br>".format(
                                        rt[i]['fields'][j]['type']['ofType']['name']))
                                # NOT NULL
                                elif rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type'][
                                    'kind'] == "NON_NULL":
                                    output_file.write("<span class='type'>!{0}</span><br>".format(
                                        rt[i]['fields'][j]['type']['ofType']['name']))
                                # CUSTOM TYPE
                                else:
                                    output_file.write("<span class='type'>{0}</span><br>".format(
                                        rt[i]['fields'][j]['type']['ofType']['name']))
                            # --------------------
                            x = 0
                            # Prepare a list of ARGS names for queries, mutations and subscriptions
                            # --------------------
                            # My super BOOLEAN IF, used to switch between ENABLED custom types parameter (-c)
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
                                            "<span>{0}</span><br>".format(
                                                rt[i]['fields'][j]['args'][x]['defaultValue']))
                                    # ARGS name
                                    if rt[i]['fields'][j]['args'][x]['name'] is not None:
                                        output_file.write("<span class='argument'>{0}</span>&nbsp;&nbsp;".format(
                                            rt[i]['fields'][j]['args'][x]['name']))
                                    # ARGS description
                                    if rt[i]['fields'][j]['args'][x]['description'] is not None and \
                                            rt[i]['fields'][j]['args'][x]['description'] != '':
                                        output_file.write("<span class='description'>{0}</span><br>".format(
                                            rt[i]['fields'][j]['args'][x]['description']))
                                    # --------------------
                                    # Printing out ARGS types
                                    # Data -> Schema -> Types -> Fields -> Args -> Type (name, ofType, kind)
                                    # TODO half a bug: there are custom objects that have multiple types as the following example
                                    # in this case ![LIST], at the moment this specific case is handled casting the returning value of
                                    # rt[i]['fields'][j]['args'][x]['type']['ofType']['name'] to STRING
                                    # in order to prevent errors (None type concatenated to a string)
                                    # we are missing the custom object but at least the script does not falls apart
                                    """
                                         "description":null,
                                         "isDeprecated":false,
                                         "args":[  ],
                                         "deprecationReason":null,
                                         "type":{  
                                            "kind":"NON_NULL",
                                            "name":null,
                                            "ofType":{  
                                               "kind":"LIST",
                                               "name":null,
                                               "ofType":{  
                                                  "kind":"NON_NULL",
                                                  "name":null,
                                                  "ofType":{  
                                                     "kind":"SCALAR",
                                                     "name":"String",
                                                     "ofType":null
                                                  }
                                               }
                                            }
                                         },
                                         "name":"roles"
                                    """
                                    # --------------------
                                    if rt[i]['fields'][j]['args'][x]['type'] is not None and (
                                            rt[i]['name'] not in primitives) and (
                                            rt[i]['kind'] not in advanced_kind):
                                        # LIST
                                        if rt[i]['fields'][j]['args'][x]['type']['kind'] == "LIST":
                                            output_file.write("<span class='type'>[{0}]</span><br>".format(
                                                rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                        # NOT NULL
                                        elif rt[i]['fields'][j]['args'][x]['type']['kind'] == "NON_NULL":
                                            output_file.write("<span class='type'>{0}!</span><br>".format(
                                                rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                        # Holds simple types like float, string, int etc.
                                        else:
                                            if rt[i]['fields'][j]['args'][x]['type']['name'] is not None:
                                                output_file.write("<span class='type'>{0}</span><br>".format(
                                                    rt[i]['fields'][j]['args'][x]['type']['name']))
                                    x += 1
                            j += 1
                    i += 1
        # For None key exceptions use: except KeyError:
        except Exception:
            raise
        # Close documentation
        output_file.write("</body></html>")
        output_file.close()
