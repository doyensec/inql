from __future__ import print_function
import json

from inql.utils import open


def generate(argument, fpath="introspection.json", green_print=lambda s: print(s)):
    """
    Generate Schema JSON

    :param argument: introspection query output
    :param fpath: file output
    :return: None
    """
    green_print("Writing Introspection Schema JSON")
    with open(fpath, "w") as schema_file:
        schema_file.write(json.dumps(argument, indent=4, sort_keys=True))
    green_print("DONE")