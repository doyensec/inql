from __future__ import print_function
from inql.cycles import Graph, CyclesDetector
from inql.utils import simplify_introspection


def generate(argument, fpath="cycles.txt", timeout=60, streaming=False, green_print=lambda s: print(s)):
    """
    Generate Cycles Founds file, or stream to stdout

    :param argument: introspection query result
    :param fpath: output result, if streaming is not enabled
    :param timeout: exits cycle detector after that timeout
    :param streaming: if True all the cycles will be outputed to stdout without being saved anywhere, useful when
                      dealing with huge graphs
    :return: None
    """
    simple_introspection = simplify_introspection(argument)
    g = Graph(simple_introspection)
    g.create()
    cycles = CyclesDetector(g, timeout)
    if streaming:
        global i
        i = 0
        green_print("Streaming Query Cycles")

        def print_cycle(cycle):
            global i
            i += 1
            print("%s: %s" % (i, CyclesDetector.cycle_str(cycle)))

        cycles.detect(on_cycle=print_cycle)
    else:
        green_print("Writing Query Cycles to %s" % fpath)
        cycles.detect()
        with open(fpath, 'w') as f:
            f.write(str(cycles))
        green_print("DONE")