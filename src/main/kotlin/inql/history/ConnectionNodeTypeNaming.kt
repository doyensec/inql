package inql.history

/**
 * Canonical naming for connection node types in history schema recreation.
 *
 * - When response evidence provides `__typename`, that name wins.
 * - Otherwise the node type is always Parent + ConnectionField (e.g. Organization + teams → OrganizationTeams).
 *
 * Error-path inference and SDL registration must use the same rule so corrections land on the wired type.
 */
internal object ConnectionNodeTypeNaming {
    /**
     * Namespaced APIs often use PascalCase field names that match the object type
     * (e.g. Query.NaptimeQueries → type NaptimeQueries).
     */
    fun child(parentType: String, fieldName: String): String {
        if (fieldName.isNotEmpty() && fieldName[0].isUpperCase() && fieldName.none { it == '_' }) {
            return fieldName
        }
        return synthetic(parentType, fieldName)
    }

    fun synthetic(parentType: String, connectionField: String): String {
        return parentType + connectionField.toGraphQLPascalCase()
    }
}
