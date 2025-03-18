package inql.graphql.formatting

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
        private val globalCache = HashMap<String, HashMap<Long, String>>()
        private val styleCache = HashMap<String, HashMap<Long, List<StyleMetadata>>>()

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
        if (!globalCache.containsKey(this.cacheKey)) {
            globalCache[this.cacheKey] = HashMap()
            styleCache[this.cacheKey] = HashMap()
        }
    }

    private fun getCache(query: String): String? {
        val hash = getQueryHash(query)
        return globalCache[this.cacheKey]!![hash]
    }

    private fun getStyleCache(query: String): List<StyleMetadata> {
        val hash = getQueryHash(query)
        return styleCache[cacheKey]!![hash]!!
    }

    private fun setCache(query: String, formatted: String, style: List<StyleMetadata>) {
        val hash = getQueryHash(query)
        globalCache[this.cacheKey]!![hash] = formatted
        styleCache[this.cacheKey]!![hash] = style
    }

    private fun makeIndent(level: Int): String {
        return " ".repeat(level * this.spaces)
    }

    fun format(query: String): Pair<String, List<StyleMetadata>> {
        val cached = this.getCache(query)
        if (cached != null) {
            val cachedStyle = this.getStyleCache(query)
            return Pair(cached, cachedStyle)
        }

        var tokens = Tokenizer(query).tokenize()
        tokens = SyntaxParser.parse(tokens, isIntrospection)
        if (stripComments) {
            tokens = tokens.filter { it.type != Token.Type.COMMENT }
        }
        val (formattedStr, formattedStyle) = this.format(tokens)
        CoroutineScope(Dispatchers.Default).launch { this@Formatter.setCache(query, formattedStr, formattedStyle) } // We don't need to wait for this
        return Pair(formattedStr, formattedStyle)
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
