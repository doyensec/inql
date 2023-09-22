package inql.graphql.formatting

class Formatter(
    val minimized: Boolean = false,
    val spaces: Short = 4,
    val stripComments: Boolean = false,
    val asHTML: Boolean = false,
    val isIntrospection: Boolean = false,
) {
    companion object {
        fun format(query: String, minimized: Boolean = false, spaces: Short = 4, asHTML: Boolean = false): String {
            return Formatter(minimized, spaces, asHTML).format(query)
        }

        fun formatAsHTML(query: String, minimized: Boolean = false, spaces: Short = 4): String {
            return Formatter(minimized, spaces, true).format(query)
        }
    }

    private fun makeIndent(level: Int): String {
        return " ".repeat(level * this.spaces)
    }

    fun format(query: String): String {
        var tokens = Tokenizer(query).tokenize()
        tokens = SyntaxParser.parse(tokens, isIntrospection)
        if (stripComments) {
            tokens = tokens.filter { it.type != Token.Type.COMMENT }
        }
        return this.format(tokens)
    }

    fun format(tokens: List<Token>): String {
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
                                "${token.print(this.asHTML)} ${tokens[index + 1].print(this.asHTML)} ${
                                    tokens[index + 2].print(
                                        this.asHTML,
                                    )
                                } ${tokens[index + 3].print(this.asHTML)}",
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
}
