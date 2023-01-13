import gqlpy


class GQLType(object):
    name = ''          # type: str
    kind = None        # type: gqlpy.GQLTypeKind
    schema = None      # type: gqlpy.GQLSchema
    description = ''   # type: str
    fields = None      # type: gqlpy.GQLFields
    interfaces = None  # type: gqlpy.GQLInterfaces
    enums = None       # type: gqlpy.GQLEnums
    args = None      # type: gqlpy.GQLArgs
    url = ''           # type: str

    def __init__(self, name, kind, schema, description='', fields=None, interfaces=None, enums=None, args=None, url=''):
        self.name = name
        self.kind = kind
        self.schema = schema
        self.description = ''
        self.fields = fields
        self.interfaces = interfaces
        self.enums = enums
        self.args = args
        self.url = url

    @staticmethod
    def from_json(json, schema):
        wrap = gqlpy.GQLWrapFactory(schema, json)

        return GQLType(
            name=json['name'],
            kind=gqlpy.GQLTypeKind(json),
            schema=schema,
            description=json.get('description', ''),

            fields     = wrap.fields(),
            interfaces = wrap.interfaces(),
            enums      = wrap.enums(),
            args       = wrap.args(),

            url=json.get('specifiedByURL', '')
        )

    def __repr__(self):
        return '"{name}" ({kind}) - {description} - [fields: {fields}] [interfaces: {interfaces}] [enums: {enums}] [ args: {args}]'.format(
            name        = self.name,
            kind        = self.kind.kind,
            description = self.description,
            fields      = ', '.join([str(x) for x in self.fields]),
            interfaces  = ', '.join([str(x) for x in self.interfaces]),
            enums       = ', '.join([str(x) for x in self.enums]),
            args        = ', '.join([str(x) for x in self.args])
        )
