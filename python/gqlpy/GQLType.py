import gqlpy


class GQLType:
    name = ''          # type: str
    kind = None        # type: gqlpy.GQLTypeKind
    schema = None      # type: gqlpy.GQLSchema
    description = ''   # type: str
    fields = None      # type: List[gqlpy.gqlpy.GQLTypeProxy]
    interfaces = None  # type: List[gqlpy.gqlpy.GQLTypeProxy]
    enums = None       # type: List[gqlpy.gqlpy.GQLEnum]
    inputs = None      # type: List[gqlpy.gqlpy.GQLArg]
    url = ''           # type: str

    def __init__(self, name, kind, schema, description='', fields=None, interfaces=None, enums=None, inputs=None, url=''):
        self.name = name
        self.kind = kind
        self.schema = schema
        self.description = ''
        self.fields = fields
        self.interfaces = interfaces
        self.enums = enums
        self.inputs = inputs
        self.url = url

    @staticmethod
    def _wrap_typeref(json, schema, name):
        types = []
        for value in (json.get(name, []) or []):
            if 'type' in value:
                kind = gqlpy.GQLTypeKind(value['type'])
            elif 'kind' in value:
                kind = gqlpy.GQLTypeKind(value)
            else:
                print("wtf, I don't get this", name, value)
                print()
                print(json)
            types.append(gqlpy.GQLTypeProxy(kind.name, schema))
        return types

    @staticmethod
    def _wrap_fields(json, schema):
        fields = []
        for value in (json.get('fields', []) or []):
            field = gqlpy.GQLField.from_json(value, schema)
            fields.append(field)
        return fields

    @staticmethod
    def _wrap_enums(json):
        enums = []
        for enum in (json.get('enumValues', []) or []):
            enums.append(gqlpy.GQLEnum.from_json(enum))
        return enums

    @staticmethod
    def _wrap_inputs(json, schema):
        inputs = []
        for i in (json.get('inputFields', []) or []):
            inputs.append(gqlpy.GQLArg.from_json(i, schema))
        return inputs

    @staticmethod
    def from_json(json, schema):
        return GQLType(
            name=json['name'],
            kind=gqlpy.GQLTypeKind(json),
            schema=schema,
            description=json.get('description', ''),
            fields=GQLType._wrap_fields(json, schema),
            interfaces=GQLType._wrap_typeref(json, schema, 'interfaces'),
            enums=GQLType._wrap_enums(json),
            inputs=GQLType._wrap_inputs(json, schema),
            url=json.get('specifiedByURL', '')
        )

    def __repr__(self):
        return '"{name}" ({kind}) - {description} - [fields: {fields}] [interfaces: {interfaces}] [enums: {enums}] [ inputs: {inputs}]'.format(
            name        = self.name,
            kind        = self.kind.kind,
            description = self.description,
            fields      = ', '.join([str(x) for x in self.fields]),
            interfaces  = ', '.join([str(x) for x in self.interfaces]),
            enums       = ', '.join([str(x) for x in self.enums]),
            inputs      = ', '.join([str(x) for x in self.inputs])
        )