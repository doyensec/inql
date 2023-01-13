import gqlpy


class GQLSchema(object):
    types          = None  # type: gqlpy.GQLTypes
    query          = None  # type: gqlpy.GQLType
    mutation       = None  # type: gqlpy.GQLType
    _query_type    = None  # type: str
    _mutation_type = None  # type: str

    def __init__(self, url, extra_headers=None):
        introspection_result = self.send_request(url, extra_headers)
        original_schema = introspection_result['data']['__schema']

        self._query_type    = original_schema['queryType']['name']
        self._mutation_type = original_schema['mutationType']['name']

        self.types = gqlpy.GQLTypes(self, original_schema)

        self.query          = self.types[self._query_type]
        self.mutation       = self.types[self._mutation_type]

    @staticmethod
    def send_request(url, extra_headers=None, minimize=True):
        import requests
        from gqlpy.introspection_query import get_introspection_query

        headers = {'Content-Type': 'application/json'}
        if extra_headers:
            headers.update(extra_headers)

        result = requests.post(url, json={'query': get_introspection_query(minimize=minimize)}, headers=headers).json()
        if 'errors' in result:
            raise Exception([error['message'] for error in result['errors']])

        return result

    def generate_query(self, name):
        if type(name) == str:
            field = self.query.fields[name]
        else:
            field = name
        return gqlpy.GQLQuery(self.query, 'query', fields=[field])

    def generate_mutation(self, name):
        if type(name) == str:
            field = self.query.fields[name]
        else:
            field = name
        return gqlpy.GQLQuery(self.mutation, 'mutation', fields=[field])

    def print_sample_queries(self):
        for field in self.query.fields:
            query = gqlpy.GQLQuery(self.query, 'query', fields=[field])

            print("Query '%s.graphql':" % field.name)
            query_string = self.generate_query(field)\
                .print_query()\
                .splitlines()
            print('\n'.join('    ' + line for line in query_string))
            print("")
