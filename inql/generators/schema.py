import json

from inql.utils import open


def generate(argument, fpath="introspection.json"):
    """
    Generate Schema JSON

    :param argument: introspection query output
    :param fpath: file output
    :return: None
    """
    with open(fpath, "w") as schema_file:
        schema_file.write(json.dumps(argument, indent=4, sort_keys=True))