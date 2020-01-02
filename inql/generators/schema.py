import json
from inql.utils import open


def generate(argument, fpath="introspection.json"):
    with open(fpath, "w") as schema_file:
        schema_file.write(json.dumps(argument, indent=4))