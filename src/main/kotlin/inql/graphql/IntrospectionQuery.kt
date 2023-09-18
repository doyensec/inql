package inql.graphql

class IntrospectionQuery {
    enum class Version {
        JUN2018,
        OCT2021,
        DRAFT
    }

    companion object {
        private val query = """
            query IntrospectionQuery {
                __schema {
                    # Typically query is called "Query" and mutation "Mutation", but those can be redefined.
                    # For some reason, spec does not force queryType[name] to be String!, but I don't think it can be null.
                    queryType {
                        name
                    }
                    # 'mutationType' can be null if there are no mutations.
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
                            args%s {
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
                        inputFields%s {
                            ... InputValue
                        }
                        # The following is only non-null for LIST and NON_NULL:
                        ofType {
                            ... TypeRef
                        }
                        # Only (optionally) non-null for custom scalars:
                        %s
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
        """.trimIndent()

        fun get(version: Version): String {
            var includeDeprecatedArgsAndInputFields = ""
            var specifiedByURL = ""
            if (version > Version.JUN2018) specifiedByURL = "specifiedByURL"
            if (version > Version.OCT2021) includeDeprecatedArgsAndInputFields = "(includeDeprecated: true)"
            return query.format(
                includeDeprecatedArgsAndInputFields,
                includeDeprecatedArgsAndInputFields,
                specifiedByURL
            )
        }
    }
}