package inql.graphql.formatting

import burp.api.montoya.ui.Theme
import java.awt.Color

object Style {
    public enum class StyleClass {
        STRING,
        NUMBER,
        COMMENT,
        SYMBOL,
        FIELD,
        TYPE,
        ARGUMENT,
        KEYWORD,
        FRAGMENT,
        VALUE,
        OBJECT,
        VARIABLE,
        OPNAME,
        OPERATION,
        ALIAS,
        DIRECTIVE,
        NONE
    }

    fun getClass(t: Token): StyleClass {
        return when (t.type) {
            Token.Type.STRING -> StyleClass.STRING
            Token.Type.NUMBER -> StyleClass.NUMBER
            Token.Type.COMMENT -> StyleClass.COMMENT
            Token.Type.PUNCTUATOR -> StyleClass.SYMBOL
            Token.Type.EMPTY -> StyleClass.NONE
            Token.Type.NAME -> {
                when (t.subtype) {
                    Token.Subtype.FIELD_NAME -> StyleClass.FIELD
                    Token.Subtype.TYPE -> StyleClass.TYPE
                    Token.Subtype.ARGUMENT_NAME -> StyleClass.ARGUMENT
                    Token.Subtype.KEYWORD -> StyleClass.KEYWORD
                    Token.Subtype.FRAGMENT_NAME -> StyleClass.FRAGMENT
                    Token.Subtype.VALUE -> StyleClass.VALUE
                    Token.Subtype.OBJECT_NAME -> StyleClass.OBJECT
                    Token.Subtype.VARIABLE_NAME -> StyleClass.VARIABLE
                    Token.Subtype.OPERATION_NAME -> StyleClass.OPNAME
                    Token.Subtype.OPERATION_TYPE -> StyleClass.OPERATION
                    Token.Subtype.ALIAS_NAME -> StyleClass.ALIAS
                    Token.Subtype.DIRECTIVE_NAME -> StyleClass.DIRECTIVE
                    Token.Subtype.NONE -> StyleClass.NONE
                }
            }
        }
    }

    private val darkAttributeSetThemeStyle = mapOf(
        StyleClass.STRING to Color(146, 197, 99),
        StyleClass.NUMBER to Color(249, 155, 86),
        StyleClass.COMMENT to Color(192, 192, 192),
        StyleClass.NONE to Color(192, 192, 192),
        StyleClass.SYMBOL to Color(192, 192, 192),
        StyleClass.FIELD to Color(233, 191, 99),
        StyleClass.TYPE to Color(117, 181, 223),
        StyleClass.ARGUMENT to Color(144, 238, 144),
        StyleClass.KEYWORD to Color(255, 255, 255),
        StyleClass.FRAGMENT to Color(255, 140, 0),
        StyleClass.VALUE to Color(249, 155, 86),
        StyleClass.OBJECT to Color(233, 191, 99),
        StyleClass.VARIABLE to Color(247, 146, 218),
        StyleClass.OPNAME to Color(255, 140, 0),
        StyleClass.OPERATION to Color(255, 255, 255),
        StyleClass.ALIAS to Color(36, 214, 199),
        StyleClass.DIRECTIVE to Color(255, 239, 159),
    )

    private val lightAttributeSetThemeStyle = mapOf(
        StyleClass.STRING to Color(27, 141, 26),
        StyleClass.NUMBER to Color(28, 28, 255),
        StyleClass.COMMENT to Color(192, 192, 192),
        StyleClass.NONE to Color(192, 192, 192),
        StyleClass.SYMBOL to Color(32,32,32),
        StyleClass.FIELD to Color(203, 153, 33),
        StyleClass.TYPE to Color(32, 159, 243),
        StyleClass.ARGUMENT to Color(56, 142, 56),
        StyleClass.KEYWORD to Color(32, 32, 32),
        StyleClass.FRAGMENT to Color(255, 131, 11),
        StyleClass.VALUE to Color(28, 28, 255),
        StyleClass.OBJECT to Color(56, 142, 56),
        StyleClass.VARIABLE to Color(243, 75, 195),
        StyleClass.OPNAME to Color(255, 131, 11),
        StyleClass.OPERATION to Color(32, 32, 32),
        StyleClass.ALIAS to Color(28, 168, 157),
        StyleClass.DIRECTIVE to Color(165, 177, 37),
    )

    val STYLE_COLORS_BY_THEME = mapOf(
        Theme.DARK to darkAttributeSetThemeStyle,
        Theme.LIGHT to lightAttributeSetThemeStyle
    )
}
