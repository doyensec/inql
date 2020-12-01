from __future__ import print_function

from inql.generators.query import recurse_fields
from inql.utils import simplify_introspection, open

def extract_args(val, returns):
    """
    Recursive method that extract all the arguments name available in the present queries

    :param val: the IIR sub value, already recursively rebuilt
    :param returns: the support set containing the return value, it should be empty on the first iteration
    """
    if type(val) is not dict:
        return returns

    for k, v in val.items():
        if k == 'args':
            # extract returns also work as a name inference for arguments due to the json struct
            extract_returns(v, returns)
        if type(v) is dict:
            extract_args(v, returns)

    return returns


def extract_args_types(val, returns):
    """
    Recursive method that extract all the arguments types available in the present queries

    :param val: the IIR sub value, already recursively rebuilt
    :param returns: the support set containing the return value, it should be empty on the first iteration
    """
    if type(val) is not dict:
        returns.add(val)
        return returns

    for k, v in val.items():
        if k == 'args':
            # extract returns types also work as a name inference for arguments due to the json struct
            extract_returns_types(v, returns)
        if type(v) is dict:
            extract_args_types(v, returns)

    return returns

def extract_returns(val, returns):
    """
    Recursive method that extract all the returns name available in the present queries

    :param val: the IIR sub value, already recursively rebuilt
    :param returns: the support set containing the return value, it should be empty on the first iteration
    """
    if type(val) is not dict:
        return returns

    for k, v in val.items():
        if k == 'args':
            continue
        if type(v) is dict:
            extract_returns(v, returns)
        else:
            returns.add(k)

    return returns


def extract_returns_types(val, returns):
    """
    Recursive method that extract all the returns types available in the present queries

    :param val: the IIR sub value, already recursively rebuilt
    :param returns: the support set containing the return value, it should be empty on the first iteration
    """
    if type(val) is not dict:
        returns.add(val)
        return returns

    for k, v in val.items():
        if k == 'args':
            continue
        if type(v) is dict:
            extract_returns_types(v, returns)
        else:
            returns.add(v)

    return returns


def joinset(input_set):
    return ', '.join(input_set)


def generate(argument, fpath="endpoints_%.tsv"):
    """
    Generate Cycles Founds file, or stream to stdout

    :param argument: introspection query result
    :param fpath: output result format string, the first %s will be used as query type (mutation, susbscription, ...)
    :return: None
    """
    s = simplify_introspection(argument)

    rev = {}
    for t, v in s.items():
        for k in v.keys():
            rev[k] = t

    for qtype, qvalues in s['schema'].items():
        rec = recurse_fields(s, rev, qvalues['type'], non_required_levels=2)
        path = fpath % qtype
        with open(path, "w") as tsv_file:
            tsv_file.write("Operation Name\tArgs Name\tArgs Types\tReturns Name\tReturns Types\n")
            for qname, qval in rec.items():
                tsv_file.write("%s\t%s\t%s\t%s\t%s\n" % (qname,
                                       joinset(extract_args(qval, set())),
                                       joinset(extract_args_types(qval, set())),
                                       joinset(extract_returns(qval, set())),
                                       joinset(extract_returns_types(qval, set()))))