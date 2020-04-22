from __future__ import print_function

from inql.utils import string_join, open


def detect_type(types):
    """
    This function will replace known GraphQL arguments types with placeholder values (useful for Burp Suite Repeater)

    :param types:
        Known types: String, Boolean, Float, Int, NOT_NULL
        TODO: add the support for custom objects and lists (partially handled since v4.1)

    :return:
        Returns a placeholder accordingly to the provided type
    """
    # strip the ! character (not null symbol) before returning the type
    types = types.replace("!", "")
    # Switch between known args types
    if "String" in types:
        # needed for Burp Repeater string handling
        types = string_join('\\"', types, '\\"')
        types = types.replace("String", "asd")
    elif "Boolean" in types:
        types = types.replace("Boolean", "true")
    elif "Float" in types:
        types = types.replace("Float", "0.5")
    elif "Int" in types:
        types = types.replace("Int", "1")
    return types


def query_write(opath, type, qname, content, mode):
    """
    This function is used in order to generate the Queries Mutations & Subscriptions templates.
    Path and file name will be generated as follow:

    :param opath:
        query path template it needs two %s to work

    :param type:
        query, mutation, subscription

    :param qname:
        query, mutation, subscription names

    :param content:
        file content

    :param mode:
        w, a and so on

    :return:
        none
    """
    with open(opath % (type, '%s.query' % qname), mode) as ofile:
        ofile.write(content)


def generate(argument, custom=False, qpath="%s/%s", detect=True, green_print=lambda s: print(s)):
    """
    Generate query templates

    :param argument: introspection query result
    :param custom: enable or disable custom types, disabled by default
    :param qpath:
        directory template where to output the queries, first parameter is type of query and second is query name

    :param detect:
        retrieve placeholders according to arg type

    :param green_print:
        implements print in green

    :return: None
    """
    # -----------------------
    # Setup lists for templates generation
    # -----------------------
    q_name = []
    q_args_name = []
    q_args_type = []
    q_type = []
    m_name = []
    m_args_name = []
    m_args_type = []
    m_type = []
    s_name = []
    s_args_name = []
    s_args_type = []
    s_type = []
    # holds custom objects
    # [[obj name 1,field name 1,field name 2],[obj name 2,field name 1,field name 2, field name 3]]
    fields_names = []

    result = argument.copy()

    try:
        # Print available operation types, usually: Query, Mutations & Subscriptions
        # This part also holds custom names (schema[Type]['name'] != 'RootQuery', 'RootMutation', 'Subscriptions')
        # --------------------
        if result['data']['__schema']['mutationType'] is not None:
            Mutation = result['data']['__schema']['mutationType']['name']
        else:
            # Needed since not all GraphQL endpoints use/have all the three types (Query, Mutations & Subscriptions)
            Mutation = None
        if result['data']['__schema']['queryType'] is not None:
            Query = result['data']['__schema']['queryType']['name']
        else:
            Query = None
        if result['data']['__schema']['subscriptionType'] is not None:
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
                    # Print our types RootQuery, RootMutation, Subscriptions
                    # --------------------
                    # Handles custom objects (FIELDS)
                    if rt[i]['kind'] == "OBJECT" and rt[i]['name'] is not None:
                        fields_names.append([rt[i]['name']])
                        xxx += 1
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
                                # Get field name and its type, if none is an advanced element (es. list) and we get it from ofType
                                q_name.append(rt[i]['fields'][j]['name'])
                                q_args_name.append([])
                                if rt[i]['fields'][j]['type']['name'] is not None:
                                    q_type.append(rt[i]['fields'][j]['type']['name'])
                                else:
                                    q_type.append(rt[i]['fields'][j]['type']['ofType']['name'])
                            # Mutation
                            elif rt[i]['name'] == Mutation:
                                # Get field name and its type, if none is an advanced element (es. list) and we get it from ofType
                                m_name.append(rt[i]['fields'][j]['name'])
                                m_args_name.append([])
                                if rt[i]['fields'][j]['type']['name'] is not None:
                                    m_type.append(rt[i]['fields'][j]['type']['name'])
                                else:
                                    m_type.append(rt[i]['fields'][j]['type']['ofType']['name'])
                            # Subscription
                            elif rt[i]['name'] == Subscription:
                                # Get field name and its type, if none is an advanced element (es. list) and we get it from ofType
                                s_name.append(rt[i]['fields'][j]['name'])
                                s_args_name.append([])
                                if rt[i]['fields'][j]['type']['name'] is not None:
                                    s_type.append(rt[i]['fields'][j]['type']['name'])
                                else:
                                    s_type.append(rt[i]['fields'][j]['type']['ofType']['name'])
                            # It handle custom objects
                            elif rt[i]['kind'] == "OBJECT":
                                # here I  add the args name the field list
                                # xxx-1 since it will be incremented after the assign, otherwise list out of bound
                                fields_names[xxx - 1].append(rt[i]['fields'][j]['name'])
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
                                # ARGS name
                                if rt[i]['fields'][j]['args'][x]['name'] is not None:
                                    # Will append the ARG name to the correct list
                                    # based on if it is an argument from query, mutation or subscription
                                    # --------------------
                                    if rt[i]['name'] == Query:
                                        q_args_name[j].append(rt[i]['fields'][j]['args'][x]['name'])
                                    elif rt[i]['name'] == Mutation:
                                        m_args_name[j].append(rt[i]['fields'][j]['args'][x]['name'])
                                    elif rt[i]['name'] == Subscription:
                                        s_args_name[j].append(rt[i]['fields'][j]['args'][x]['name'])
                                    # --------------------
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
                                        if rt[i]['name'] == Query:
                                            q_args_type.append(
                                                "[%s]" % str(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                        elif rt[i]['name'] == Mutation:
                                            m_args_type.append(
                                                "[%s]" % str(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                        elif rt[i]['name'] == Subscription:
                                            s_args_type.append(
                                                "[%s]" % str(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                    # NOT NULL
                                    elif rt[i]['fields'][j]['args'][x]['type']['kind'] == "NON_NULL":
                                        if rt[i]['name'] == Query:
                                            q_args_type.append(
                                                "!%s" % str(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                        elif rt[i]['name'] == Mutation:
                                            m_args_type.append(
                                                "!%s" % str(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                        elif rt[i]['name'] == Subscription:
                                            s_args_type.append(
                                                "!%s" % str(
                                                    rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
                                    # Holds simple types like float, string, int etc.
                                    else:
                                        if rt[i]['fields'][j]['args'][x]['type']['name'] is not None:
                                            if rt[i]['name'] == Query:
                                                q_args_type.append(
                                                    str(rt[i]['fields'][j]['args'][x]['type']['name']))
                                            elif rt[i]['name'] == Mutation:
                                                m_args_type.append(
                                                    str(rt[i]['fields'][j]['args'][x]['type']['name']))
                                            elif rt[i]['name'] == Subscription:
                                                s_args_type.append(
                                                    str(rt[i]['fields'][j]['args'][x]['type']['name']))
                                # --------------------
                                x += 1
                        j += 1
                i += 1
    # For None key exceptions use: except KeyError:
    except Exception:
        raise
    # Writing templates
    # Reverse args list in order to use pop
    q_args_type.reverse()
    m_args_type.reverse()
    s_args_type.reverse()
    # replacing None items to String for a smooth exec
    q_type = list(map(str, q_type))
    m_type = list(map(str, m_type))
    s_type = list(map(str, s_type))
    # --------------------
    # QUERY
    # --------------------
    green_print("Writing Queries Templates")
    index = 0
    for qname in q_name:
        print(" |  %s" % str(qname))
        query_write(qpath, "query", qname, "{\"query\":\"query %s {%s" % (qname, qname), "w")
        if len(q_args_name[index]) != 0:
            query_write(qpath, "query", qname, "(", "a")
            for argsname in q_args_name[index]:
                # POP out of the list empty values
                if argsname != "":
                    # if detect type (-d param) is enabled, retrieve placeholders according to arg type
                    if detect:
                        query_write(qpath, "query", qname,
                                   "%s:%s " % (argsname, detect_type(q_args_type.pop())), "a")
                    else:
                        query_write(qpath, "query", qname,
                                   "%s:%s " % (argsname, q_args_type.pop()), "a")
                else:
                    q_args_type.pop()
            # Query name
            query_write(qpath, "query", qname, ")", "a")
        # Query fields
        f_index = 0
        fields_str = ""
        for fieldsnames in fields_names:
            if q_type[index] in fields_names[f_index][0]:
                for items in fields_names[f_index][1:]:
                    fields_str += "\\n\\t%s " % items
                break
            f_index += 1
        # Close query
        if fields_str != "":
            query_write(qpath, "query", qname, "{%s\\n}" % fields_str, "a")
        query_write(qpath, "query", qname, "\\n}\"}", "a")
        index += 1
    # --------------------
    # MUTATION
    # --------------------
    green_print( "Writing Mutations Templates")
    index = 0
    for mname in m_name:
        print(" |  %s" % str(mname))
        query_write(qpath, "mutation", mname, "{\"query\":\"mutation{%s(" % mname, "w")
        for argsname in m_args_name[index]:
            # POP out of the list empty values
            if argsname != "":
                # if detect type (-d param) is enabled, retrieve placeholders according to arg type
                if detect:
                    query_write(qpath, "mutation", mname,
                               "%s:%s " % (argsname, detect_type(m_args_type.pop())), "a")
                else:
                    query_write(qpath, "mutation", mname,
                               "%s:%s " % (argsname, m_args_type.pop()), "a")
            else:
                m_args_type.pop()
        # Mutation name
        query_write(qpath, "mutation", mname, ")", "a")
        # Mutation fields
        fields_str = ""
        f_index = 0
        for fieldsnames in fields_names:
            if m_type[index] in fields_names[f_index][0]:
                for items in fields_names[f_index][1:]:
                    fields_str += "\\n\\t%s " % items
                break
            f_index += 1
        # Close mutation
        if fields_str != "":
            query_write(qpath, "mutation", mname, "{%s\\n}" % fields_str, "a")
        query_write(qpath, "mutation", mname, "\\n}\"}", "a")
        index += 1
    # --------------------
    # SUBSCRIPTION
    # --------------------
    green_print("Writing Subscriptions Templates")
    index = 0
    for sname in s_name:
        print(" |  %s" % str(sname))
        query_write(qpath, "subscription", sname, "{\"query\":\"subscription{%s(" % sname,
                   "w")
        for argsname in s_args_name[index]:
            # POP out of the list empty values
            if argsname != "":
                # if detect type (-d param) is enabled, retrieve placeholders according to arg type
                if detect:
                    query_write(qpath, "subscription", sname,
                               "%s:%s " % (argsname, detect_type(s_args_type.pop())), "a")
                else:
                    query_write(qpath, "subscription", sname,
                               "%s:%s " % (argsname, s_args_type.pop()), "a")
            else:
                s_args_type.pop()
        # Subscription name
        query_write(qpath, "subscription", sname, ")", "a")
        # Subscription fields
        f_index = 0
        fields_str = ""
        for fieldsnames in fields_names:
            if s_type[index] in fields_names[f_index][0]:
                for items in fields_names[f_index][1:]:
                    fields_str += "\\n\\t%s " % items
                break
            f_index += 1
        # Close subscription
        if fields_str != "":
            query_write(qpath, "subscription", sname, "{%s\\n}" % fields_str, "a")
        query_write(qpath, "subscription", sname, "\\n}\"}", "a")
        index += 1
    # --------------------
    # THE END, they all lived happily ever after (hopefully)
    green_print("DONE")