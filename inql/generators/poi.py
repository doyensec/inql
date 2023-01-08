from inql.utils import simplify_introspection
GRAPHQL_BUILTINS = ["Int", "String", "ID", "Boolean", "Float"]
class Graph:
    def __init__(self,graph=None,data=None):
        self.graph = graph or {}
        self.data = data or {}
    def get(self,node_name):
        node = self.graph.get(node_name,False)
        if node:
            return node
        else:
            breakpoint()
            self.data[node_name]
            
    def __str__(self):
        return ""
    def __repr__(self):
        return ""
class Node:
    def __init__(self,name,ntype='',inputs=None,children=None,parents=None,raw=None):
        self.name = name
        self.ntype = ntype or "Object"
        self.inputs = inputs or ...
        self.children = children or {}
        self.parents = parents or {}
        self.raw = raw or {}
    def add_child(self,field_name,child):
        self.children[field_name] = child
    def add_parent(self,parent):
        self.parents[parent.name] = parent
    def __str__(self):
        return f"{self.ntype}(name={self.name})"
    def __repr__(self):
        return f"{self.ntype}(name={self.name})"
    def __hash__(self):
        return hash((self.name,self.ntype))
    def __eq__(self,other):
        return isinstance(other,Node) and (self.name,self.ntype) == (other.name,self.ntype)
    def __ne__(self,other):
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
    schema = [Node(name=v["type"],ntype=k) for k,v in si["schema"].items()]
    # all nodes will have a name and their corresponding object
    graph = Graph(data=si["type"])
    # get high level function names and return types
    for query in schema:
        for func,data in si["type"].pop(query.name).items():
            function_gqlo = Node(name=func,type="function",raw=data)

            
            function_gqlo.add_child(nodes[data["type"]])
            query.add_child(function_gqlo)
    
    breakpoint()