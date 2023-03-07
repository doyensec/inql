# coding: utf-8
import json
import re


def is_query(body):
    # FIXME: add a quicker screening test, to avoid heavy JSON processing
    # FIXME: handle urlencoded requests too in the future
    try:
        content = json.loads(body)
        if not isinstance(content, list):
            content = [content]

        ret = all(['query' in c for c in content])
        return ret
    except:
        return False


# Source of the regex: https://spec.graphql.org/June2018/#sec-Names
VALID_GRAPHQL_NAMES = re.compile('^[_A-Za-z][_0-9A-Za-z]*$')


def is_valid_graphql_name(name):
    return VALID_GRAPHQL_NAMES.match(name) is not None
