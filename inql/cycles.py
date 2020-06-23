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
        """
          function connectVertices() {
    for ( var vertex in Graph) {
      for ( var ref in Graph[vertex].referenceList) {
        var reference = Graph[vertex].referenceList[ref].reference;
        edges++;
        if(Graph[reference] === undefined)
        {
          if(excludeList.includes(reference))
          {
            Graph[reference] = {"vertexID": reference, "referenceList":[]};
          } // added to avoid when someone refers to the subscription|query|mutation types
          else
          {
            throw new Error("Field " + reference +  " not defined");
          }
        }
        Graph[vertex].referenceList[ref].reference = Graph[reference];
      }
    }
  }

        """
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