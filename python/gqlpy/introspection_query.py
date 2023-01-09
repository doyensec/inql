__documented_introspection_query = """
query IntrospectionQuery {
    __schema {
        # Typically query is called "Query" and mutation "Mutation", but you those can be redefined
        queryType {
            name
        }
        mutationType {
            name
        }
        # TODO: We're not parsing subscriptions and directives at all right now
        # subscriptionType { name }
        # directives { name }
        types {
            name
            # 'kind' is enum with values: SCALAR, OBJECT, INTERFACE, UNION, ENUM, INPUT_OBJECT, LIST, NON_NULL
            kind
            description
            # The following are only present for OBJECT and INTERFACE, otherwise null:
            fields(includeDeprecated: true) {
                name
                description
                args(includeDeprecated: true) {
                    ... InputValue
                }
                type {
                    ... TypeRef
                }
                isDeprecated
                deprecationReason
            }
            interfaces {
                ... TypeRef
            }
            # The following is only non-null for INTERFACE and UNION:
            possibleTypes {
                ... TypeRef
            }
            # The following is only non-null for ENUM:
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            # The following is only non-null for INPUT_OBJECT:
            inputFields(includeDeprecated: true) {
                ... InputValue
            }
            # The following is only non-null for LIST and NON_NULL:
            ofType {
                ... TypeRef
            }
            # Only (optionally) non-null for custom scalars:
            specifiedByURL
        }
    }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

# TODO: generate this query dynamically and make the depth adjustable
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


# TODO: 'depth' is ignored right now, fix it
def get_introspection_query(depth=4, minimize=True):
    """Construct the introspection query and optionally minimize it."""
    from gqlpy.utils import minimize_query
    if minimize:
        return minimize_query(__documented_introspection_query)
    else:
        return __documented_introspection_query
