class Graph:
    def __init__(self, data):
        self.data = data
        self._representation = {}
        self.vertices = 0
        self.edges = 0
        self.graphQLTypes = ["Int", "String", "ID", "Boolean", "Float"]
        self.excludeList = ["Mutation", "Query", "Subscription"]
        self._created = False

    def _add_to_graph(self, target):
        for object_name in self.data[target]:
            derived_by = []
            if '__implements' in self.data[target][object_name]:
                derived_by = self.data[target][object_name]['__implements'].keys()
            is_derived = len(derived_by) > 0

            if object_name not in self.excludeList:
                self.vertices += 1
                object_type = self.data[target][object_name]

                tmp_reference_list = []

                for fields in object_type.keys():
                    if target == 'union':
                        type_name = fields
                    else:
                        if fields[0:2] == "__":
                            continue
                        type_name = object_type[fields]['type']

                    if type_name not in self.graphQLTypes:
                        if target == 'union':
                            tmp_reference_list.append({
                                "label": "#union_ref",
                                "reference": fields
                            })
                        else:
                            tmp_reference_list.append({
                                "label": fields,
                                "reference": object_type[fields]['type']
                            })

                if is_derived:
                    # this implies that the interface vertexes has been already added
                    for der in derived_by:
                        self._representation[der]['referenceList'].append({
                            "label": "#interface_ref", "reference": object_name
                        })

                self._representation[object_name] = {
                    "vertexID": object_name,
                    "vertexType": target,
                    "referenceList": tmp_reference_list
                }

    def _connect(self):
        for vertex in self._representation.keys():
            for ref, ref_object in enumerate(self._representation[vertex]['referenceList']):
                reference = ref_object['reference']
                self.edges += 1
                if reference not in self._representation:
                    if reference in self.excludeList:
                        self._representation[reference] = {"vertexID": reference, "referenceList":[]}
                    else:
                        raise Exception("Field %s not defined" % reference)
                ref_object['reference'] = self._representation[reference]

    def __repr__(self):
        return str({
            "vertices": self.vertices,
            "edges": self.edges
        })

    def __str__(self):
        s = "Graph("
        for vertex in self._representation.keys():
            s += "\n\t%s" % self._representation[vertex]['vertexID']
            for reference, _ in enumerate(self._representation[vertex]['referenceList']):
                s += "\n\t\t-> %s" % self._representation[vertex]['referenceList'][reference]['reference']['vertexID']
        s += "\n)"
        return s

    def create(self):
        if self._created:
            return self._representation

        for basic_type in ['enum', 'scalar']:
            if basic_type in self.data:
                self.graphQLTypes += self.data[basic_type].keys()

        self._add_to_graph("interface")

        self._add_to_graph("union")

        self._add_to_graph("type")

        self._connect()

        self._created = True

        return self._representation

class CyclesDetector:
    def __init__(self, graph):
        self.graph = graph
        self.save_mode = 1
        self.data = None

    def detect(self, select=False):
        if self.data:
            return self.data

        data = {}
        data['foundCycle'] = False
        data['cycles'] = []
        data['numberCycles'] = 0
        tarjan = TarjanAlgorithm(self.graph, select)
        tarjan.execute()

        data['SCCs'] = len(tarjan.scc)
        data['longestSCC'] = 0

        for component, _ in enumerate(tarjan.scc):
            if len(tarjan.scc[component]) > data['longestSCC']:
                data['longestSCC'] = len(tarjan.scc[component])

        if select:
            data['foundCycle'] = tarjan.found_cycle
            return data

        tarjan.prune_edges()

        for i, _ in enumerate(tarjan.scc):
            try:
                johnson = JohnsonAlgorithm(tarjan.scc[i])
                johnson.execute()
                data['cycles'] += johnson.cycles
                data['numberCycles'] += len(johnson.cycles)
            except Exception as ex:
                print(ex)
                print("#Cycles found = %s" % len(johnson.cycles))
                data['numberCycles'] += len(johnson.cycles)
                data['cycles'] += johnson.cycles
                return data

        data['foundCycle'] = (len(data['cycles']) > 0)

        self.data = data

        return self

    def __repr__(self):
        return str(self.data)

    def __str__(self):
        s = "Cycles("
        if self.data:
            for sc, _ in enumerate(self.data['cycles']):
                s += "\n\t{ "
                for vert, _ in enumerate(self.data['cycles'][sc]):
                    s += self.data['cycles'][sc][vert]['vertex']['vertexID']
                    if self.data['cycles'][sc][vert]['refLabel'] == '#interface_ref':
                        s += "<~implements~ "
                    elif self.data['cycles'][sc][vert]['refLabel'] == '#union_ref':
                        s += " -union-> "
                    elif self.data['cycles'][sc][vert]["refLabel"]:
                        s += " -[%s]-> " % self.data['cycles'][sc][vert]["refLabel"]
                    else:
                        s += " }"
        s += "\n)"
        return s


class TarjanAlgorithm:
    # XXX: It will have destructive effect on the graph object
    def __init__(self, graph, select):
        self.graph = graph._representation
        self.stack = []
        self.index = 0
        self.found_cycle = False
        self.scc = []
        self.input = select

    def execute(self):
        for vertex in self.graph.keys():
            if self.found_cycle:
                return True
            elif 'visited' not in self.graph[vertex]:
                self.strong_connect(self.graph[vertex])

    def strong_connect(self, vertex):

        vertex['index'] = self.index
        vertex['lowlink'] = self.index
        self.index += 1
        self.stack.append(vertex)
        vertex['visited'] = True
        vertex['onStack'] = True
        for reference, _ in enumerate(vertex['referenceList']):

            if 'visited' not in vertex['referenceList'][reference]['reference']:
                self.strong_connect(vertex['referenceList'][reference]['reference'])
                vertex['lowlink'] = min(vertex['lowlink'], vertex['referenceList'][reference]['reference']['lowlink'])
            elif 'onStack' in vertex['referenceList'][reference]['reference'] and \
                    vertex['referenceList'][reference]['reference']['onStack']:
                vertex['lowlink'] = min(vertex['lowlink'], vertex['referenceList'][reference]['reference']['index'])
                if self.input:
                    self.found_cycle = True
                    return

        if vertex['lowlink'] == vertex['index']:
            tmp_scc = []
            w = self.stack.pop()
            w['lowlink'] = vertex['index']
            w['onStack'] = False
            w['jIndex'] = len(tmp_scc) # XXX: Used in johnson later
            tmp_scc.append(w)
            while w != vertex:
                w = self.stack.pop()
                w['lowlink'] = vertex['index']
                w['onStack'] = False
                w['jIndex'] = len(tmp_scc) # XXX: Used in johnson later
                tmp_scc.append(w)
            self.scc.append(tmp_scc)

    def prune_edges(self):
        scc = self.scc
        for component, _ in enumerate(scc):
            for vertex, _ in enumerate(scc[component]):
                tmp_reference_list = scc[component][vertex]['referenceList'][:] # copy list to operate on that
                i = 0
                for ref, _ in enumerate(scc[component][vertex]['referenceList']):
                    if scc[component][vertex]['referenceList'][ref]['reference']['lowlink'] != scc[component][vertex]['lowlink']:
                        del tmp_reference_list[ref+i]
                        i -= 1
                scc[component][vertex]['referenceList'] = tmp_reference_list


class JohnsonAlgorithm:
    def __init__(self, component):
        self.component = component
        self.cycles = []

        self.blocked = [False for _ in self.component]
        self.blocked_map = [[] for _ in self.component]
        self.stack = []
        self.stack_edges = []
        self.found_cycle = False
        self.start_vertex = 0

    def execute(self):
        for vertex, _ in enumerate(self.component):
            self.start_vertex = vertex
            self.find_cycles(vertex)
            self.blocked = [False for _ in self.component]
            self.blocked_map = [[] for _ in self.component]

    def unblock(self, u):
        self.blocked[u] = False
        for w, _ in enumerate(self.blocked_map[u]):
            target_block = self.blocked_map[u][w]
            if self.blocked[target_block]:
                self.unblock(target_block)
        self.blocked_map[u] = []

    def find_cycles(self, v):
        result = []
        self.stack.append(v) # push indexdx of vertex (in component)
        self.blocked[v] = True
        for edge, _ in enumerate(self.component[v]['referenceList']):
            edge_ref = self.component[v]['referenceList'][edge]
            if edge_ref['reference']['jIndex'] == self.start_vertex:
                self.found_cycle = True
                self.stack_edges.append(edge_ref['label'])

                for item, _ in enumerate(self.stack):
                    result.append({
                        "vertex": self.component[self.stack[item]],
                        "refLabel": self.stack_edges[item]
                    })
                result.append({
                    "vertex": self.component[self.start_vertex],
                    "refLabel": ""
                })
                if self.stack_edges: self.stack_edges.pop()
                # save result
                self.cycles.append(result)
                result = []
            elif not self.blocked[edge_ref['reference']['jIndex']] and self.start_vertex < edge_ref['reference']['jIndex'] \
                and edge_ref['reference']['jIndex'] not in self.stack:
                self.stack_edges.append(edge_ref['label'])
                self.found_cycle = self.find_cycles(edge_ref['reference']['jIndex']) # bug ?

        if self.found_cycle:
            self.unblock(v)
        else:
            for wt, _ in enumerate(self.component[v]['referenceList']):
                w = self.component[v]['referenceList'][wt]['reference']['jIndex']
                if v not in self.blocked_map[w]:
                    self.blocked_map[w].append(v)

        if self.stack: self.stack.pop()
        if self.stack_edges: self.stack_edges.pop()
        return self.found_cycle