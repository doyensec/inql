package inql.graphql.formatting

import inql.Config
import inql.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.apache.commons.codec.digest.MurmurHash3

class Formatter(
    val minimized: Boolean = false,
    val spaces: Short = 4,
    val stripComments: Boolean = false,
    val isIntrospection: Boolean = false,
) {
    companion object {
        val globalCache = HashMap<String, HashMap<Long, Pair<String, List<StyleMetadata>>>>()

        private fun getQueryHash(query: String): Long {
            /*
            For now we don't handle collisions, this should be unique enough for this use case
             */
            return MurmurHash3.hash128(query.toByteArray())[0]
        }
        fun format(query: String, minimized: Boolean = false, spaces: Short = 4): Pair<String, List<StyleMetadata>> {
            return Formatter(minimized, spaces).format(query)
        }
    }

    private val cacheKey = "$minimized$spaces$stripComments$isIntrospection"

    init {
        val maxBytes = Config.getInstance().getInt("editor.formatting.cache_size_kb") ?: 102400
        if (!globalCache.containsKey(this.cacheKey)) {
            globalCache[this.cacheKey] = SizedLRUCache<Long, Pair<String, List<StyleMetadata>>>(
               1024L * maxBytes
            ) { key, value ->
                8L +                        // key: Long
                16L +                       // Pair object overhead (object header + 2 refs)
                value.first.length * 2L +   // String character data
                40L +                       // String object + internal overhead
                24L +                       // List object + internal structure
                value.second.size * 32L     // Each StyleMetadata ~32 bytes
            }
        }
    }

    private fun getCache(query: String): Pair<String, List<StyleMetadata>>? {
        val hash = getQueryHash(query)
        return globalCache[this.cacheKey]!![hash]
    }

    private fun setCache(query: String, element: Pair<String, List<StyleMetadata>>) {
        Logger.debug("Cache size: #${globalCache[this.cacheKey]?.size}, ~ ${estimateGlobalCacheSize() / 1024}Kb, ")
        val hash = getQueryHash(query)

        globalCache[this.cacheKey]!![hash] = element
    }

    fun estimateGlobalCacheSize(): Long {
        var total = 0L
        for ((outerKey, innerMap) in globalCache) {
            total += outerKey.length * 2L + 64L // outer String key + map overhead
            for ((_, pair) in innerMap) {
                val stringPart = pair.first
                val styleList = pair.second

                total += 8L                      // innerKey: Long
                total += 16L                     // Pair object overhead (2 refs)
                total += stringPart.length * 2L // String character data
                total += 40L                     // String object overhead
                total += 24L                     // List object overhead
                total += styleList.size * 32L   // StyleMetadata items (~32B each)
                total += 48L                     // entry overhead (Map.Entry)
            }
        }
        return total
    }

    private fun makeIndent(level: Int): String {
        return " ".repeat(level * this.spaces)
    }

    fun format(query: String): Pair<String, List<StyleMetadata>> {
        val cached = this.getCache(query)
        if (cached != null) {
            return cached
        }

        var tokens = Tokenizer(query).tokenize()
        tokens = SyntaxParser.parse(tokens, isIntrospection)
        if (stripComments) {
            tokens = tokens.filter { it.type != Token.Type.COMMENT }
        }

        val result: Pair<String, List<StyleMetadata>> = this.format(tokens)
        CoroutineScope(Dispatchers.Default).launch { this@Formatter.setCache(query, result) } // We don't need to wait for this
        return result
    }

    private fun format(tokens: List<Token>): Pair<String, List<StyleMetadata>> {
        val result = StringBuilder()
        val highlightInfo = ArrayList<StyleMetadata>()
        var indentLevel = 0
        var firstTopLevelToken: Token? = null
        var newline = false

        fun appendToken(token: Token) {
            if (token.styleClass != Style.StyleClass.NONE) {
                highlightInfo.add(StyleMetadata(result.length, token.text.length, token.styleClass))
            }
            result.append(token.text)
        }

        fun newLine(indentLevel: Int) {
            result.append("\n")
            result.append(makeIndent(indentLevel))
        }

        // Count the depth of complex inputs
        var complexInputLevel = 0

        // Iterate over the tokens with ability to jump forward
        var index = -1
        var token: Token
        while (index + 1 < tokens.size) {
            index++
            token = tokens[index]

            /*
             process operation names (query, mutation, subscription) and 'fragment' keyword
             operation names only have special meaning at the top level and only if they are the first token
             */
            if (indentLevel == 0) {
                if (firstTopLevelToken == null) {
                    firstTopLevelToken = token

                    if (setOf("query", "mutation", "subscription").contains(token.text)) {
                        appendToken(token)
                        result.append(" ")
                        newline = false
                        continue
                    }

                    if (token.text == "fragment") {
                        // fragment A on B { ... }
                        if (index + 3 < tokens.size && tokens[index + 2].text == "on") {
                            appendToken(token)
                            result.append(" ")
                            appendToken(tokens[index + 1])
                            result.append(" ")
                            appendToken(tokens[index + 2])
                            result.append(" ")
                            appendToken(tokens[index + 3])
                            index += 3
                            newline = false
                            continue
                        }
                    }
                }
            } else {
                firstTopLevelToken = null
            }

            // check for the start of a block
            if (token.text == "{") {
                // '{' is also used for complex input variables and it shouldn't be followed by newline in that case
                if (complexInputLevel > 0) {
                    complexInputLevel++
                    appendToken(token)
                    result.append(" ")
                    newline = false
                    continue
                }

                if (index > 0 && setOf(":", "=").contains(tokens[index - 1].text)) {
                    complexInputLevel = 1
                    appendToken(token)
                    result.append(" ")
                    newline = false
                    continue
                }

                if (index > 0 && tokens[index - 1].text[0] == '#') {
                    // if the previous line was a comment, we need to add a newline before the block
                    newLine(indentLevel)
                }

                indentLevel++

                // '{' should be separated from the previous token by a space, but it might have been added already
                if (result.isNotEmpty() && !result.last().isWhitespace()) {
                    result.append(" ")
                }

                appendToken(token)
                newLine(indentLevel)
                newline = false
                continue
            } else if (token.text == "}") {
                if (complexInputLevel > 0) {
                    complexInputLevel--
                    result.append(" ")
                    appendToken(token)
                    newline = false
                    continue
                }
                indentLevel--
                newLine(indentLevel)
                appendToken(token)
                newline = true
                continue
            } else if (setOf(",", ":").contains(token.text)) {
                // check for the tokens that has to be followed by a space
                appendToken(token)
                result.append(" ")
                newline = false
                continue
            } else if (token.text[0] == '@') {
                // check for the tokens that has to be preceded by a space
                result.append(" ")
                appendToken(token)
                newline = false
                continue
            } else if (token.text == "...") {
                // '...' has complex rules, so we'll handle it separately
                /*
                 inline fragments are used like this:
                   ... on User
                 regular fragments are used like this (fragment name can not be 'on'):
                   ...UserFragment
                 */
                if (newline) {
                    newLine(indentLevel)
                }
                newline = false
                if (tokens.size > index + 1 && tokens[index + 1].text == "on") {
                    appendToken(token)
                    result.append(" ")
                    appendToken(tokens[index + 1])
                    result.append(" ")
                    index++
                    continue
                } else {
                    appendToken(token)
                    continue
                }
            } else if (setOf("=", "|").contains(token.text)) {
                // tokens that need to be surrounded by spaces
                result.append(" ")
                appendToken(token)
                result.append(" ")
                newline = false
                continue
            } else if (setOf("$", "!", "(", "[", "]").contains(token.text)) {
                // tokens that are used as is (no spaces)
                appendToken(token)
                newline = false
                continue
            } else if (token.text == ")") {
                // ')' needs special handling - it doesn't need a space, but it could indicate the end of a line
                newline = true
                appendToken(token)
                continue
            } else if (token.text[0] == '#') {
                // newline at the end of the comment is a hack to signalize that it's a whole line comment
                if (token.text.last() == '\n') {
                    token.text = token.text.removeSuffix("\n")
                    if (newline) {
                        if (result.isNotEmpty() && result.last() != '\n') {
                            // whole line comment, add a newline before
                            newLine(indentLevel)
                            appendToken(token)
                        } else {
                            // whole line comment, but there is a newline already
                            result.append(makeIndent(indentLevel))
                            appendToken(token)
                        }
                    } else {
                        appendToken(token)
                    }
                } else {
                    // inline comment, no newline but add a space before
                    result.append(" ")
                    appendToken(token)
                }
                newline = true
                continue
            } else {
                if (newline) {
                    newLine(indentLevel)
                    appendToken(token)
                } else {
                    appendToken(token)
                }
                newline = true
                continue
            }
        }
        return Pair(result.toString(), highlightInfo.toList())
    }
}
