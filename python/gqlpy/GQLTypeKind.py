class GQLTypeKind:
    """Construct a type out of GraphQL schema fragment.

    Type kinds are stored in the 'kind' property, which is defined by __TypeKind enum:

        enum __TypeKind {
          SCALAR
          OBJECT
          INTERFACE
          UNION
          ENUM
          INPUT_OBJECT
          LIST             # wrapping type, need to check 'ofType' to construct the whole type
          NON_NULL         # wrapping type, need to check 'ofType' to construct the whole type
        }

    Additionally, note that the introspection_query we use only queries first level data, the nested types only return
    name and kind. That is, in order to query fields, interfaces, possibleTypes, enumValues, inputFields, inputFields,
    ofType and specifiedByURL you need to use the first-level definition within the schema[].

    A typedef is schema fragment such as:

        {u'kind': u'NON_NULL',
         u'name': None,
         u'ofType': {u'kind': u'LIST',
          u'name': None,
          u'ofType': {u'kind': u'NON_NULL',
           u'name': None,
           u'ofType': {u'kind': u'OBJECT',
            u'name': u'BillingPlanV2',
            u'ofType': None}}}}

    """
    wrapping_types = ('LIST', 'NON_NULL')
    non_wrapping_types    = ('SCALAR', 'OBJECT', 'INTERFACE', 'UNION', 'ENUM', 'INPUT_OBJECT')

    leaf_types = ('SCALAR', 'ENUM')

    # FIXME: populate the list of built-in types defined in GraphQL spec
    builtin_types = ()

    modifiers = None   # in the example above: [NON_NULL, LIST, NON_NULL]
    kind = None        # in the example above: OBJECT
    name = None        # in the example above: 'BillingPlanV2'

    def __init__(self, typedef):
        current = typedef
        self.modifiers = []
        while current['kind'] in self.wrapping_types:
            # iterate through intermediate modifiers (LIST and NON_NULL)
            self.modifiers.append(current['kind'])
            current = current['ofType']

        # by this time all modifiers should have been parsed, make sure the result is what we expect
        if current['kind'] not in self.non_wrapping_types:
            raise Exception("Type '%s' is of unknown kind: '%s'" % (typedef['name'], typedef['kind']))

        self.kind = current['kind']
        self.name = current['name']

    # String representation (in the example above: "[BillingPlanV2!]!")
    def __repr__(self):
        string_representation = self.name
        for modifier in reversed(self.modifiers):
            if modifier == 'NON_NULL':
                string_representation += '!'
            if modifier == 'LIST':
                string_representation = "[%s]" % string_representation

        return string_representation

    @property
    def is_builtin(self):
        return self.name in self.builtin_types

    @property
    def is_leaf(self):
        return self.kind in self.leaf_types
