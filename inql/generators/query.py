from __future__ import print_function

import json

from inql.utils import open, simplify_introspection


def recurse_fields(schema, reverse_lookup, t, max_nest=7, non_required_levels=1, dinput=None,
                   params_replace=lambda schema, reverse_lookup, elem: elem):
    """
    Generates a JSON representation of the AST object representing a query

    :param schema:
        the output of a simplified schema

    :param reverse_lookup:
        a support hash that goes from typename to graphql type, useful to navigate the schema in O(1)

    :param t:
        type that you need to generate the AST for, since it is recursive it may be anything inside the graph

    :param max_nest:
        maximum number of recursive calls before returning the type name, this is needed in particularly broken cases
        where recurse_fields may not exit autonomously (EG. hackerone.com is using union to create sql or/and/not
        statements.) Consider that this will partially break params_replace calls.

    :param non_required_levels:
        expand up to non_required_levels levels automatically.

    :param dinput:
        the output object, it may even be provided from the outside.

    :param params_replace:
        a callback that takes (schema, reverse_lookup, elem) as parameter and returns a replacement for parameter.
        Needed in case you want to generate real parameters for queries.

    """
    if max_nest == 0:
        return params_replace(schema, reverse_lookup, t)
    if t not in reverse_lookup:
        return params_replace(schema, reverse_lookup, t)

    if dinput == None:
        dinput = {}

    if reverse_lookup[t] in ['type', 'interface', 'input']:
        for inner_t, v in schema[reverse_lookup[t]][t].items():
            if inner_t == '__implements':
                for iface in v.keys():
                    interface_recurse_fields = recurse_fields(schema, reverse_lookup, iface, max_nest=max_nest,
                                                              non_required_levels=non_required_levels,
                                                              params_replace=params_replace)
                    dinput.update(interface_recurse_fields)
                continue
            recurse = non_required_levels > 0 or v['required']  # required_only => v['required']
            if recurse:
                dinput[inner_t] = recurse_fields(schema, reverse_lookup, v['type'], max_nest=max_nest - 1,
                                                 non_required_levels=non_required_levels - 1,
                                                 params_replace=params_replace)
            if 'args' in v:
                if inner_t not in dinput or type(dinput[inner_t]) is not dict:
                    dinput[inner_t] = {}
                dinput[inner_t]["args"] = {}
                for inner_a, inner_v in v['args'].items():
                    recurse_inner = non_required_levels > 0 or inner_v['required']  # required_only => v['required']
                    if recurse:
                        arg = recurse_fields(schema, reverse_lookup, inner_v['type'], max_nest=max_nest - 1,
                                             non_required_levels=non_required_levels - 1, params_replace=params_replace)
                        if 'array' in inner_v and inner_v['array']:
                            if type(arg) is dict:
                                arg = [arg]
                            else:
                                arg = "[%s]" % arg
                        if 'required' in inner_v and inner_v['required']:
                            if type(arg) is not dict:
                                arg = "!%s" % arg
                            else:
                                pass  # XXX: don't handle required array markers, this is a bug, but simplifies a lot the code
                        dinput[inner_t]['args'][inner_a] = arg
                if len(dinput[inner_t]["args"]) == 0:
                    del dinput[inner_t]["args"]
                if len(dinput[inner_t]) == 0:
                    del dinput[inner_t]

        if len(dinput) == 0 and (t not in reverse_lookup or reverse_lookup[t] not in ['enum', 'scalar']):
            inner_t, v = list(schema[reverse_lookup[t]][t].items())[0]
            dinput[inner_t] = recurse_fields(schema, reverse_lookup, v['type'], max_nest=max_nest - 1,
                                             non_required_levels=non_required_levels - 1, params_replace=params_replace)
    elif reverse_lookup[t] == 'union':
        # select the first type of the union
        first_union_type = list(schema['union'][t].keys())[0]
        return recurse_fields(schema, reverse_lookup, first_union_type, max_nest=max_nest,
                              non_required_levels=non_required_levels, params_replace=params_replace)
    elif reverse_lookup[t] in ['enum', 'scalar']:
        # return the type since it is an enum
        return params_replace(schema, reverse_lookup, t)
    return dinput


def dict_to_args(d):
    """
    Generates a string representing query arguments from an AST dict.

    :param d: AST dict
    """
    args = []
    for k, v in d.items():
        args.append("%s:%s" % (k, json.dumps(v).replace('"', '').replace("u'", "").replace("'", "").replace('@', '"')))
    if len(args) > 0:
        return "(%s)" % ', '.join(args)
    else:
        return ""


def dict_to_qbody(d, prefix=''):
    """
    Generates a string representing a query body from an AST dict.

    :param d: AST dict
    :param prefix: needed in case it will recurse
    """
    if type(d) is not dict:
        return ''
    s = ''
    iprefix = prefix + '\t'
    args = ''
    for k, v in d.items():
        if k == 'args':
            args = dict_to_args(v)
        elif type(v) is dict:
            s += '\n' + iprefix + k + dict_to_qbody(v, prefix=iprefix)
        else:
            s += '\n' + iprefix + k
    if len(s) > 0:
        return "%s {%s\n%s}" % (args, s, prefix)
    else:
        return args


def preplace(schema, reverse_lookup, t):
    """
    Replaces basic types and enums with default values.

    :param schema:
        the output of a simplified schema

    :param reverse_lookup:
        a support hash that goes from typename to graphql type, useful to navigate the schema in O(1)

    :param t:
        type that you need to generate the AST for, since it is recursive it may be anything inside the graph

    """
    if t == 'String':
        return '@code@'
    elif t == 'Int':
        return 1334
    elif t == 'Boolean':
        return 'true'
    elif t == 'Float':
        return 0.1334
    elif t == 'ID':
        return 14
    elif reverse_lookup[t] == 'enum':
        return list(schema['enum'][t].keys())[0]
    elif reverse_lookup[t] == 'scalar':
        # scalar may be any type, so the AST can be anything as well
        # since the logic is custom implemented I have no generic way of replacing them
        # for this reason we return it back as they are
        return t
    else:
        return t


def generate(argument, qpath="%s/%s", detect=True, green_print=lambda s: print(s)):
    """
    Generate query templates

    :param argument: introspection query result
    :param qpath:
        directory template where to output the queries, first parameter is type of query and second is query name

    :param detect:
        retrieve placeholders according to arg type

    :param green_print:
        implements print in green

    :return: None
    """
    s = simplify_introspection(argument)

    rev = {}
    for t, v in s.items():
        for k in v.keys():
            rev[k] = t

    for qtype, qvalues in s['schema'].items():
        green_print("Writing %s Templates" % qtype)
        if detect:
            rec = recurse_fields(s, rev, qvalues['type'], non_required_levels=2, params_replace=preplace)
        else:
            rec = recurse_fields(s, rev, qvalues['type'], non_required_levels=2)
        for qname, qval in rec.items():
            print("Writing %s %s" % (qname, qtype))
            with open(qpath % (qtype, '%s.query' % qname), 'w') as ofile:
                body = "%s {\n\t%s%s\n}" % (qtype, qname, dict_to_qbody(qval, prefix='\t'))
                if detect:
                    body = body.replace('!', '')
                query = {"query": body}
                ofile.write(json.dumps(query))

    green_print("DONE")