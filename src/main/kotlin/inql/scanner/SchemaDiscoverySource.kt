package inql.scanner

/**
 * How the GraphQL schema for a scan was obtained.
 */
enum class SchemaDiscoverySource {
    /** Standard introspection query succeeded. */
    INTROSPECTION,

    /** User supplied a schema file (JSON or SDL). */
    FILE,

    /** Introspection failed or was unavailable; schema was recovered via Apollo Federation `_service { sdl }`. */
    FEDERATION_SDL_FALLBACK,

    /** Schema produced by the schema bruteforcer. */
    BRUTEFORCE,
    ;

    /** Short label for the scan tree node, e.g. `(Introspection)`. */
    val treeLabelSuffix: String
        get() = when (this) {
            INTROSPECTION -> "Introspection"
            FILE -> "Schema File"
            FEDERATION_SDL_FALLBACK -> "Federation SDL"
            BRUTEFORCE -> "Bruteforced"
        }
}
