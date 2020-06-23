from inql.cycles import Graph, CyclesDetector
from inql.utils import simplify_introspection, run_timeout


def generate(argument, fpath="cycles.txt", timeout=60):
    def real_generate():
        simple_introspection = simplify_introspection(argument)
        g = Graph(simple_introspection)
        g.create()
        cycles = CyclesDetector(g).detect()
        with open(fpath, 'w') as f:
            f.write(str(cycles))

    run_timeout(execute=real_generate, timeout=timeout)