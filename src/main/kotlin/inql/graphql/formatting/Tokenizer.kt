package inql.graphql.formatting

class Tokenizer(val query: String) {
    private var index = 0
    private val length = query.length

    fun tokenize(): List<Token> {
        /* Tokenize the GraphQL request."""
         GraphQL ignores whitespace (outside strings and comments) and commas
         Tokens:
           Punctuator      !	$	&	(	)	...	:	=	@	[	]	{	|	}
           Name            starts with letter, continues letters, digits, _
           IntValue
           FloatValue
           StringValue     but """ starts a block string
         */

        /*
         iterate over each character in the query, keeping track of context within the query
         detect the start & end of tokens and add them to the list
           - don't modify strings
           - don't modify comments
         */

        val tokens = ArrayList<Token>()

        while (this.index < this.length) {
            this.nextToken()
            if (this.index >= this.length) break

            val token: Token = when (val chr = this.query[this.index]) {
                '"' -> readString()
                '#' -> readComment()
                '!', '$', '(', ')', '.', ',', ':', '=', '@', '[', ']', '{', '|', '}' -> readPunctuator()
                '-', '+', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' -> readNumber()
                '_', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' -> readName()
                else -> throw Exception("Unexpected character $chr at position ${this.index}")
            }
            tokens.add(token)
        }
        return tokens
    }

    private fun nextToken() {
        /* Move index to the next token */

        // Technically, in GraphQL commas could be ignored as well, but people expect them to be there
        // so we'll keep them in and filter them out later if necessary
        while (this.index < this.length && this.query[this.index].isWhitespace()) this.index++
    }

    private fun readString(): Token {
        val start = this.index
        var index = this.index
        var blockString = false

        // check for block strings - start with """ and may contain newlines
        if (this.length >= index + 3 && this.query.regionMatches(index, "\"\"\"", 0, "\"\"\"".length)) {
            blockString = true
            index += 3
        } else {
            index++
        }

        // read until the end of the string
        while (index < this.length) {
            val chr = this.query[index]

            // check for escaped characters
            when (chr) {
                '\\' -> {
                    // check for escaped unicode (\u + 4 hex digits)
                    if (index + 5 < this.length && this.query[index + 1] == 'u') {
                        index += 6
                    } else {
                        // otherwise it's a regular escaped character
                        // according to spec, only "\/bfnrt are allowed, but this could vary by implementation
                        index += 2
                    }
                }
                '"' -> {
                    if (!blockString) {
                        // End of normal string
                        index++
                        break
                    } else if (this.length >= index + 3 && this.query.regionMatches(index, "\"\"\"", 0, "\"\"\"".length)) {
                        // End of blockstring
                        index += 3
                        break
                    } else {
                        // Quote char inside a blockstring, do nothing
                    }
                }
                else -> {
                    // Normal character
                    index++
                }
            }
        }

        if (index >= this.length) {
            throw Exception("Unterminated string starting at position $start")
        }
        this.index = index
        return Token(Token.Type.STRING, this.query.substring(start, index))
    }

    /*
    This method finds all whitespace characters from start of string to "end"
    and returns true if the whitespace sequence contains a newline
     */
    private fun lookbehindNewline(s: String, end: Int): Boolean {
        for (i in end-1 downTo 0) {
            if (!s[i].isWhitespace()) return false
            if (s[i] == '\n') return true
        }
        return false
    }

    private fun readComment(): Token {
        /* Consume a comment token */
        val start = this.index

        /*
         Comments can be placed on their own line, or at the end of a line
         From the server's perspective, it doesn't matter, but it does matter to the user
         As a hack we'll do a lookbehind to see if there was a newline before the comment
         In order to separate these two styles of comments, we'll store newline (if present) at the end of the token - hack!
         */

        val onItsOwnLine = lookbehindNewline(this.query, this.index)

        // Comment ends at the end of the line (don't include the newline in the token)
        var newlineIdx = this.query.indexOf('\n', this.index)
        if (newlineIdx == -1) {
            // if there's no newline, the comment goes to the end of the query
            newlineIdx = this.length
        }
        var token = this.query.substring(start, newlineIdx)

        this.index = newlineIdx + 1
        if (onItsOwnLine) token += '\n'

        return Token(Token.Type.COMMENT, token)
    }

    private fun readPunctuator(): Token {
        /* Consume a punctuator token */
        val token: String
        if (this.length >= this.index + 3 && this.query.regionMatches(this.index, "...", 0, "...".length)) {
            token = "..."
            this.index += 3
        } else {
            token = this.query[this.index].toString()
            index++
        }
        return Token(Token.Type.PUNCTUATOR, token)
    }

    private fun readNumber(): Token {
        /* Consume a number token */
        val start = this.index
        var index = this.index

        // Read until the end of the number
        while (index < this.length && (
                this.query[index].isDigit() || setOf(
                    '.',
                    'e',
                    'E',
                    '+',
                    '-',
                ).contains(this.query[index])
                )
            ) index++
        this.index = index
        return Token(Token.Type.NUMBER, this.query.substring(start, index))
    }

    private fun readName(): Token {
        /* Consume a name token */
        val start = this.index
        var index = this.index

        while (index < this.length && (this.query[index].isLetterOrDigit() || this.query[index] == '_')) index++

        this.index = index
        return Token(Token.Type.NAME, this.query.substring(start, index))
    }
}
