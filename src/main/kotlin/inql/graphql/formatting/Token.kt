package inql.graphql.formatting

import org.apache.commons.text.StringEscapeUtils

class Token(var type: Type, var text: String) {

    var subtype: Subtype = Subtype.NONE

    enum class Type {
        STRING,
        COMMENT,
        NUMBER,
        PUNCTUATOR,
        NAME,
        EMPTY,
    }

    enum class Subtype {
        OPERATION_TYPE,
        OPERATION_NAME,
        VARIABLE_NAME,
        ARGUMENT_NAME,
        DIRECTIVE_NAME,
        FIELD_NAME,
        ALIAS_NAME,
        FRAGMENT_NAME,
        OBJECT_NAME,
        TYPE,
        KEYWORD, // "on", "fragment", ecc
        VALUE,
        NONE,
    }

    override fun toString(): String {
        return this.text
    }

    fun asHTML(): String {
        return """<span class="${Style.getClass(this)}">${StringEscapeUtils.escapeHtml4(this.text)}</span>"""
    }

    fun print(asHTML: Boolean): String {
        return if (asHTML) {
            this.asHTML()
        } else {
            this.toString()
        }
    }
}
