import gqlpy

# FIXME: Add support for InputFields


class GQLField:
    name = ''                # type: str
    description = ''         # type: str
    kind  = None             # type: gqlpy.GQLTypeKind
    type  = None             # type: gqlply.GQLType
    args = None              # type: gqlpy.GQLArg
    is_deprecated = False    # type: bool
    deprecation_reason = ''  # type: str
    schema = None            # type: gqlpy.GQLSchema

    def __init__(self, name, kind, schema, description='', args=None, is_deprecated=False, deprecation_reason=''):
        self.name = name
        self.kind = kind
        self.type = gqlpy.GQLTypeProxy(kind.name, schema)
        self.schema = schema
        self.description = description
        self.args = args
        self.is_deprecated = is_deprecated
        self.deprecation_reason = deprecation_reason

        #type_of_field = gqlpy.GQLType(field['type'])


    @staticmethod
    def _wrap_inputs(json, schema):
        args = []
        for i in (json.get('args', []) or []):
            args.append(gqlpy.GQLArg.from_json(i, schema))
        return args

    @staticmethod
    def from_json(field, schema):
        return GQLField(
            name=field['name'],
            kind=gqlpy.GQLTypeKind(field['type']),
            schema=schema,
            description=field.get('description', ''),
            args=GQLField._wrap_inputs(field, schema),
            is_deprecated=field.get('isDeprecated', False),
            deprecation_reason=field.get('deprecationReason', '')
        )
