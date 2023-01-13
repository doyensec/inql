import gqlpy


class GQLTypeProxy(object):
    name = ''      # type: str
    schema = None  # type: gqlpy.GQLSchema
    max_depth = 4  # type: int

    def __init__(self, name, schema):
        self.name = name
        self.schema = schema

    def _proxy_getattr(self, item, levels):
        if levels >= self.max_depth:
            raise Exception("reached the recursion limit!")
        return getattr(self, item)

    def __getattr__(self, item):
        upstream = self.schema.types[self.name]
        proxy = getattr(upstream, '_proxy_getattr', None)
        if proxy:
            # nested object detected, pass execution to proxy
            return proxy(item, 0)

        return getattr(upstream, item)

    def __dir__(self):
        return super(gqlpy.GQLType, self.schema.types[self.name]).__dir__()

