package inql.bruteforcer

import inql.graphql.RESERVED_LITERALS

internal interface NameSource {
    val scanArguments: Boolean

    /** Whether [inputFieldTypeHint] can answer; sources without hints skip the extra probe it needs. */
    val providesTypeHints: Boolean get() = false

    fun fieldNames(typeName: String, path: Path): List<String>

    fun argumentNames(typeName: String, path: Path, field: String): List<String>

    fun inputFieldNames(inputType: String): List<String>

    fun enumValues(enumType: String): List<String>

    fun possibleTypeNames(typeName: String, path: Path): List<String>

    /** Paths that may be scanned past the depth limit; such paths are also preferred when a type has several. */
    fun ignoresDepthLimit(path: Path): Boolean = false

    fun typesSeenAt(path: Path): List<String> = emptyList()

    fun argumentSamples(path: Path, field: String): Map<String, SampleValue> = emptyMap()

    fun inputFieldTypeHint(inputType: String, field: String): String? = null
}

internal sealed interface SampleValue {
    data class Literal(val text: String) : SampleValue

    data class Json(val declaredType: String, val value: Any?) : SampleValue
}

internal class WordlistNames(
    private val wordlist: List<String>,
    private val argumentWordlist: List<String>,
    override val scanArguments: Boolean,
) : NameSource {
    private val enumCandidates by lazy {
        (wordlist.map { it.uppercase() } + wordlist).filter { it !in RESERVED_LITERALS }.distinct()
    }

    override fun fieldNames(typeName: String, path: Path) = wordlist
    override fun argumentNames(typeName: String, path: Path, field: String) = argumentWordlist
    override fun inputFieldNames(inputType: String) = wordlist
    override fun enumValues(enumType: String) = enumCandidates
    override fun possibleTypeNames(typeName: String, path: Path) = wordlist
}
