from inql.cycles import Graph, CyclesDetector
from inql.utils import simplify_introspection


def generate(argument, fpath="cycles.txt", timeout=60):
    simple_introspection = simplify_introspection(argument)
    g = Graph(simple_introspection)
    g.create()
    cycles = CyclesDetector(g, timeout).detect()

    with open(fpath, 'w') as f:
        f.write(str(cycles))
