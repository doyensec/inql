from inql.generators.poi import Graph, Node
from inql.utils import simplify_introspection
from collections import defaultdict
import re
import json

def generate(
    argument,
    fpath="fastcycles.txt",
    streaming=False,
    green_print=lambda s: print(s),
):
    """
    Generate Report on Sensitive Field Names

    :param argument: introspection query result
    :param fpath: output result
    :param streaming: boolean trigger to output to stdout or write to file with fpath
    :return: None
    """
    green_print("Generating Fast Cycles")
    # simplify schema
    si = simplify_introspection(argument)
    # all nodes will have a name and their corresponding object
    graph = Graph(
        schema={
            v["type"]: Node(name=v["type"], ntype=k) for k, v in si["schema"].items()
        },
        data=si["type"],
        types=list(si.get("enum",{}).keys()) + list(si.get("scalar",{}).keys())
    )
    graph.generate()

    matrix,keys = graph.gen_matrix()
    matrix.SCC()
    cycles = matrix.format_cycles(list(keys))
    cycles_view = ',\n\t'.join(['->'.join(cycle) for cycle in cycles])
    cycles = f"Cycles(\n\t{cycles_view}\n)"

    if streaming:
        print(cycles)
    else:
        with open(fpath, "w") as schema_file:
            schema_file.write(cycles)