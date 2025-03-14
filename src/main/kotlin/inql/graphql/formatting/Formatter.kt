package inql.graphql.formatting

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.apache.commons.codec.digest.MurmurHash3
import javax.swing.JTextPane
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyledDocument

class Formatter(
    val minimized: Boolean = false,
    val spaces: Short = 4,
    val stripComments: Boolean = false,
    val asHTML: Boolean = false,
    val isIntrospection: Boolean = false,
) {
    companion object {
        private val globalCache = HashMap<String, HashMap<Long, String>>()

        private fun getQueryHash(query: String): Long {
            /*
            For now we don't handle collisions, this should be unique enough for this use case
             */
            return MurmurHash3.hash128(query.toByteArray())[0]
        }
        fun format(query: String, minimized: Boolean = false, spaces: Short = 4, asHTML: Boolean = false): String {
            return Formatter(minimized, spaces, asHTML).format(query)
        }

        fun formatAsHTML(query: String, minimized: Boolean = false, spaces: Short = 4): String {
            return Formatter(minimized, spaces, true).format(query)
        }

        fun formatAsStyledDoc(query: String, minimized: Boolean = false, spaces: Short = 4): StyledDocument {
            return Formatter(minimized, spaces, true).formatAsStyledDoc(query)
        }
    }

    private val cacheKey = "$minimized$spaces$stripComments$asHTML$isIntrospection"

    init {
        if (!globalCache.containsKey(this.cacheKey)) {
            globalCache[this.cacheKey] = HashMap()
        }
    }

    private fun getCache(query: String): String? {
        val hash = getQueryHash(query)
        return globalCache[this.cacheKey]!![hash]
    }

    private fun setCache(query: String, formatted: String) {
        val hash = getQueryHash(query)
        globalCache[this.cacheKey]!![hash] = formatted
    }

    private fun makeIndent(level: Int): String {
        return " ".repeat(level * this.spaces)
    }

    fun format(query: String): String {
        val cached = this.getCache(query)
        if (cached != null) {
            return cached
        }

        var tokens = Tokenizer(query).tokenize()
        tokens = SyntaxParser.parse(tokens, isIntrospection)
        if (stripComments) {
            tokens = tokens.filter { it.type != Token.Type.COMMENT }
        }
        val formatted = this.format(tokens)
        CoroutineScope(Dispatchers.Default).launch { this@Formatter.setCache(query, formatted) } // We don't need to wait for this
        return formatted
    }

    fun formatAsStyledDoc(query: String): StyledDocument {
        val cached = this.getCache(query)
//        if (cached != null) {
//            return cached
//        }

        var tokens = Tokenizer(query).tokenize()
        tokens = SyntaxParser.parse(tokens, isIntrospection)
        if (stripComments) {
            tokens = tokens.filter { it.type != Token.Type.COMMENT }
        }
        val formatted = this.formatAsStyledDoc(tokens)
//        CoroutineScope(Dispatchers.Default).launch { this@Formatter.setCache(query, formatted) } // We don't need to wait for this
        return formatted
    }

    private fun format(tokens: List<Token>): String {
        val result = StringBuilder()
        var indentLevel = 0
        var firstTopLevelToken: Token? = null
        var newline = false

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
                    result.append("\n\n")

                    firstTopLevelToken = token

                    if (setOf("query", "mutation", "subscription").contains(token.text)) {
                        result.append("${token.print(this.asHTML)} ")
                        newline = false
                        continue
                    }

                    if (token.text == "fragment") {
                        // fragment A on B { ... }
                        if (index + 3 < tokens.size && tokens[index + 2].text == "on") {
                            result.append(
                                "${token.print(this.asHTML)} ${tokens[index + 1].print(this.asHTML)} ${tokens[index + 2].print(this.asHTML)} ${tokens[index + 3].print(this.asHTML)}",
                            )
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
                    result.append("${token.print(this.asHTML)} ")
                    newline = false
                    continue
                }

                if (index > 0 && setOf(":", "=").contains(tokens[index - 1].text)) {
                    complexInputLevel = 1
                    result.append("${token.print(this.asHTML)} ")
                    newline = false
                    continue
                }

                if (index > 0 && tokens[index - 1].text[0] == '#') {
                    // if the previous line was a comment, we need to add a newline before the block
                    result.append("\n${makeIndent(indentLevel)}")
                }

                indentLevel++

                // '{' should be separated from the previous token by a space, but it might have been added already
                if (result.isNotEmpty() && !result.last().isWhitespace()) {
                    result.append(" ")
                }

                result.append("${token.print(this.asHTML)}\n${makeIndent(indentLevel)}")
                newline = false
                continue
            } else if (token.text == "}") {
                if (complexInputLevel > 0) {
                    complexInputLevel--
                    result.append(" ${token.print(this.asHTML)}")
                    newline = false
                    continue
                }
                indentLevel--
                result.append("\n${makeIndent(indentLevel)}${token.print(this.asHTML)}")
                newline = true
                continue
            } else if (setOf(",", ":").contains(token.text)) {
                // check for the tokens that has to be followed by a space
                result.append("${token.print(this.asHTML)} ")
                newline = false
                continue
            } else if (token.text[0] == '@') {
                // check for the tokens that has to be preceded by a space
                result.append(" ${token.print(this.asHTML)}")
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
                    result.append("\n${makeIndent(indentLevel)}")
                }
                newline = false
                if (tokens.size > index + 1 && tokens[index + 1].text == "on") {
                    result.append("${token.print(this.asHTML)} ${tokens[index + 1].print(this.asHTML)} ")
                    index++
                    continue
                } else {
                    result.append(token.print(this.asHTML))
                    continue
                }
            } else if (setOf("=", "|").contains(token.text)) {
                // tokens that need to be surrounded by spaces
                result.append(" ${token.print(this.asHTML)} ")
                newline = false
                continue
            } else if (setOf("$", "!", "(", "[", "]").contains(token.text)) {
                // tokens that are used as is (no spaces)
                result.append(token.print(this.asHTML))
                newline = false
                continue
            } else if (token.text == ")") {
                // ')' needs special handling - it doesn't need a space, but it could indicate the end of a line
                newline = true
                result.append(token.print(this.asHTML))
                continue
            } else if (token.text[0] == '#') {
                // newline at the end of the comment is a hack to signalize that it's a whole line comment
                if (token.text.last() == '\n') {
                    token.text = token.text.removeSuffix("\n")
                    if (newline) {
                        if (result.isNotEmpty() && result.last() != '\n') {
                            // whole line comment, add a newline before
                            result.append("\n${makeIndent(indentLevel)}${token.print(this.asHTML)}")
                        } else {
                            // whole line comment, but there is a newline already
                            result.append("${makeIndent(indentLevel)}${token.print(this.asHTML)}")
                        }
                    } else {
                        result.append(token.print(this.asHTML))
                    }
                } else {
                    // inline comment, no newline but add a space before
                    result.append(" ${token.print(this.asHTML)}")
                }
                newline = true
                continue
            } else {
                if (newline) {
                    result.append("\n${makeIndent(indentLevel)}${token.print(this.asHTML)}")
                } else {
                    result.append(token.print(this.asHTML))
                }
                newline = true
                continue
            }
        }
        return result.toString().trim()
    }

    private fun formatAsStyledDoc(tokens: List<Token>): StyledDocument {
        val result = JTextPane().styledDocument
        var indentLevel = 0
        var firstTopLevelToken: Token? = null
        var newline = false

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
//                    result.insertString(result.length,"\n\n", SimpleAttributeSet())

                    firstTopLevelToken = token

                    if (setOf("query", "mutation", "subscription").contains(token.text)) {
                        result.insertString(result.length,"${token.text} ", token.getStyle())
                        newline = false
                        continue
                    }

                    if (token.text == "fragment") {
                        // fragment A on B { ... }
                        if (index + 3 < tokens.size && tokens[index + 2].text == "on") {
                            result.insertString(result.length,
                                "${token.text} ", token.getStyle()
                            )
                            result.insertString(result.length,
                                "${tokens[index + 1].text} ", tokens[index + 1].getStyle()
                            )
                            result.insertString(result.length,
                                "${tokens[index + 2].text} ", tokens[index + 2].getStyle()
                            )
                            result.insertString(result.length,
                                "${tokens[index + 3].text}", tokens[index + 3].getStyle()
                            )
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
                    result.insertString(result.length,"${token.text} ", token.getStyle())
                    newline = false
                    continue
                }

                if (index > 0 && setOf(":", "=").contains(tokens[index - 1].text)) {
                    complexInputLevel = 1
                    result.insertString(result.length,"${token.text} ", token.getStyle())
                    newline = false
                    continue
                }

                if (index > 0 && tokens[index - 1].text[0] == '#') {
                    // if the previous line was a comment, we need to add a newline before the block
                    result.insertString(result.length,"\n${makeIndent(indentLevel)}", SimpleAttributeSet())
                }

                indentLevel++

                // '{' should be separated from the previous token by a space, but it might have been added already
                if (result.length != 0 && !result.getText(result.length,1)[0].isWhitespace()) {
                    result.insertString(result.length," ", SimpleAttributeSet())
                }

                result.insertString(result.length,"${token.text}\n${makeIndent(indentLevel)}", token.getStyle())
                newline = false
                continue
            } else if (token.text == "}") {
                if (complexInputLevel > 0) {
                    complexInputLevel--
                    result.insertString(result.length," ${token.text}", token.getStyle())
                    newline = false
                    continue
                }
                indentLevel--
                result.insertString(result.length,"\n${makeIndent(indentLevel)}${token.text}", token.getStyle())
                newline = true
                continue
            } else if (setOf(",", ":").contains(token.text)) {
                // check for the tokens that has to be followed by a space
                result.insertString(result.length,"${token.text} ", token.getStyle())
                newline = false
                continue
            } else if (token.text[0] == '@') {
                // check for the tokens that has to be preceded by a space
                result.insertString(result.length," ${token.text}", token.getStyle())
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
                    result.insertString(result.length,"\n${makeIndent(indentLevel)}", SimpleAttributeSet())
                }
                newline = false
                if (tokens.size > index + 1 && tokens[index + 1].text == "on") {
                    result.insertString(result.length,"${token.text} ", token.getStyle())
                    result.insertString(result.length,"${tokens[index + 1].text} ", tokens[index + 1].getStyle())
                    index++
                    continue
                } else {
                    result.insertString(result.length,token.text, token.getStyle())
                    continue
                }
            } else if (setOf("=", "|").contains(token.text)) {
                // tokens that need to be surrounded by spaces
                result.insertString(result.length," ${token.text} ", token.getStyle())
                newline = false
                continue
            } else if (setOf("$", "!", "(", "[", "]").contains(token.text)) {
                // tokens that are used as is (no spaces)
                result.insertString(result.length,token.text, token.getStyle())
                newline = false
                continue
            } else if (token.text == ")") {
                // ')' needs special handling - it doesn't need a space, but it could indicate the end of a line
                newline = true
                result.insertString(result.length,token.text, token.getStyle())
                continue
            } else if (token.text[0] == '#') {
                // newline at the end of the comment is a hack to signalize that it's a whole line comment
                if (token.text.last() == '\n') {
                    token.text = token.text.removeSuffix("\n")
                    if (newline) {
                        if (result.length != 0 && result.getText(result.length, 1)[0] != '\n') {
                            // whole line comment, add a newline before
                            result.insertString(result.length,"\n${makeIndent(indentLevel)}${token.text}", token.getStyle())
                        } else {
                            // whole line comment, but there is a newline already
                            result.insertString(result.length,"${makeIndent(indentLevel)}${token.text}", token.getStyle())
                        }
                    } else {
                        result.insertString(result.length,token.text, token.getStyle())
                    }
                } else {
                    // inline comment, no newline but add a space before
                    result.insertString(result.length," ${token.text}", token.getStyle())
                }
                newline = true
                continue
            } else {
                if (newline) {
                    result.insertString(result.length,"\n${makeIndent(indentLevel)}${token.text}", token.getStyle())
                } else {
                    result.insertString(result.length,token.text, token.getStyle())
                }
                newline = true
                continue
            }
        }
        return result
    }
}
