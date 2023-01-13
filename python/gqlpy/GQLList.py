import collections


class GQLList(collections.Mapping):
    """A very specific data structure for internal use. Acts as an iterable in certain instances and a dict in others.

    Characteristics:

      - Gets initialized from an iterable of some type, which should have a 'name' field
      - Upon iteration, will return original dictionaries, sorted by the 'name' field
      - Allows selecting elements both by index (gqllist[3]) and by the 'name' (gqllist['some-name'])
      - GQLList is meant for read-only data, so there is no way to add, update, delete elements
    """
    _elements = None  # type: collections.OrderedDict

    def __init__(self, elements):
        sorted_elements = sorted(elements, key=lambda i: i.name)
        self._elements = collections.OrderedDict(
            ((i.name, i) for i in sorted_elements)
        )

    def __getitem__(self, item):
        # name fields are unicode if they come from requests & JSON, but could be str if the schema
        # was imported from some other force
        # TODO: introduce normalization to str (?) at some previous stage to avoid ambiguity & subtle bugs here
        if type(item) in (str, unicode):
            return self._elements[item]
        if type(item) == int:
            key = self._elements.keys()[item]
            return self._elements[key]
        raise Exception("GQLList: unknown type: %s", type(item))

    def __iter__(self):
        return (self._elements[el] for el in self._elements)

    def __str__(self):
        return '\n'.join((str(el) for el in self._elements))

    def __repr__(self):
        first_line = "GQLList[{inner_type}]".format(
            inner_type=str(type(self._elements[0]))
        )

        other_lines = ['    ' + repr(el) for el in self._elements]

        return '\n'.join([first_line] + other_lines)

    def __nonzero__(self):
        return not not len(self._elements)

    def __len__(self):
        return len(self._elements)

    def __contains__(self, item):
        if type(item) == str:
            return item in self._elements.keys()
        else:
            return item in self._elements.values()
