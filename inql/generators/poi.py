from inql.utils import simplify_introspection
import re

GRAPHQL_BUILTINS = ["Int", "String", "ID", "Boolean", "Float"]


class Graph:
    def __init__(self, nodes=None, data=None, schema=None, functions=None):
        self.nodes = nodes or {}
        self.schema = schema or {}
        self.functions = functions or {}
        self.data = data or {}

    def node(self, node_name=None):
        if node_name:
            node = self.nodes.get(node_name, Node(node_name))
            self.nodes[node_name] = node
            return node
        else:
            return {k: v for k, v in self.nodes.items()}

    def function(self, function_name=None):
        if function_name:
            node = self.functions.get(function_name, Node(function_name))
            self.functions[function_name] = node
            return node
        else:
            return {k: v for k, v in self.functions.items()}

    def generate(self):
        for obj_name, obj_data in self.data.items():
            if obj_name in self.schema:
                node = self.schema[obj_name]
                for field_name, field_data in obj_data.items():
                    field = self.function(field_data["type"])
                    node.add_child(field_name, field)
                    field.add_parent(node)
            else:
                node = self.node(obj_name)
                for field_name, field_data in obj_data.items():
                    if field_name in ["__implements"]:
                        continue
                    elif field_data["type"].startswith(tuple(GRAPHQL_BUILTINS)):
                        field = field_data["type"]
                    else:
                        field = self.node(field_data["type"])
                        field.add_parent(node)
                    node.add_child(field_name, field)

    def __str__(self):
        return f"Graph()"

    def __repr__(self):
        return f"Graph()"

    def gen_poi(self):
        def isInteresting(s):
            return "pass" in s
        poi = {"functions":{},"nodes":[],"fields":{}}
        # interesting function names
        for node in self.schema.values():
            print(node.name)
            for name in node.children:
                if isInteresting(name):
                    arr = poi["functions"].get(node.name,[])
                    arr.append(name)
                    poi["functions"][node.name] = arr
        # interesting object names
        for name in self.nodes:
            if isInteresting(name):
                poi["nodes"].append(name)
        # interesting field names
        for node in self.nodes.values():
            for field in node.children:
                if isInteresting(field):
                    arr = poi["fields"].get(node.name,[])
                    arr.append(field)
                    poi["fields"][node.name] = arr
        return poi
    
    def gen_matrix(self):
        keys = {name:idx for idx,name in enumerate(self.nodes)}
        length = len(keys)
        matrix = [[0]*length]*length
        for node in self.nodes.values():
            row = keys[node.name]
            for field in node.children.values():
                if isinstance(field,str):
                    # must be a scalar
                    continue
                matrix[row][keys[field.name]] = 1
        return matrix
            

class Node:
    def __init__(
        self, name, ntype="", inputs=None, children=None, parents=None, raw=None
    ):
        self.name = name
        self.ntype = ntype or "Object"
        self.inputs = inputs or ...
        self.children = children or {}
        self.parents = parents or {}
        self.raw = raw or {}

    def add_child(self, field_name, child):
        self.children[field_name] = child

    def add_parent(self, parent):
        self.parents[parent.name] = parent

    def __str__(self):
        return f"{self.ntype}(name={self.name})"

    def __repr__(self):
        return f"{self.ntype}(name={self.name})"

    def __hash__(self):
        return hash((self.name, self.ntype))

    def __eq__(self, other):
        return isinstance(other, Node) and (
            (self.name, self.ntype)
            == (
                other.name,
                self.ntype,
            )
        )

    def __ne__(self, other):
        return not (self == other)


def generate(argument, fpath="cycles.txt", green_print=lambda s: print(s)):
    """
    Generate Report on Sensitive Field Names

    :param argument: introspection query result
    :param fpath: output result
    :return: None
    """
    green_print("Generating POI's")
    # simplify schema
    si = simplify_introspection(argument)
    # all nodes will have a name and their corresponding object
    graph = Graph(
        schema={
            v["type"]: Node(name=v["type"], ntype=k) for k, v in si["schema"].items()
        },
        data=si["type"],
    )
    graph.generate()

    report = graph.gen_poi()

    breakpoint()
