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
        StyleClass.COMMENT to Color(140, 140, 140),
        StyleClass.NONE to Color(140, 140, 140),
        StyleClass.SYMBOL to Color(180, 180, 180),
        StyleClass.FIELD to Color(233, 191, 99),
        StyleClass.TYPE to Color(117, 181, 223),
        StyleClass.ARGUMENT to Color(144, 238, 144),
        StyleClass.KEYWORD to Color(220, 220, 220),
        StyleClass.FRAGMENT to Color(255, 140, 0),
        StyleClass.VALUE to Color(249, 155, 86),
        StyleClass.OBJECT to Color(233, 191, 99),
        StyleClass.VARIABLE to Color(247, 146, 218),
        StyleClass.OPNAME to Color(255, 140, 0),
        StyleClass.OPERATION to Color(220, 220, 220),
        StyleClass.ALIAS to Color(36, 214, 199),
        StyleClass.DIRECTIVE to Color(240, 220, 130),
    )

    private val lightAttributeSetThemeStyle = mapOf(
        StyleClass.STRING to Color(34, 139, 34),
        StyleClass.NUMBER to Color(60, 120, 200),
        StyleClass.COMMENT to Color(150, 150, 150),
        StyleClass.NONE to Color(180, 180, 180),
        StyleClass.SYMBOL to Color(80, 80, 80),
        StyleClass.FIELD to Color(184, 115, 51),
        StyleClass.TYPE to Color(30, 120, 180),
        StyleClass.ARGUMENT to Color(90, 140, 90),
        StyleClass.KEYWORD to Color(50, 50, 50),
        StyleClass.FRAGMENT to Color(220, 110, 20),
        StyleClass.VALUE to Color(60, 120, 200),
        StyleClass.OBJECT to Color(90, 140, 90),
        StyleClass.VARIABLE to Color(200, 90, 160),
        StyleClass.OPNAME to Color(220, 110, 20),
        StyleClass.OPERATION to Color(50, 50, 50),
        StyleClass.ALIAS to Color(40, 150, 130),
        StyleClass.DIRECTIVE to Color(140, 150, 50),
    )

    val STYLE_COLORS_BY_THEME = mapOf(
        Theme.DARK to darkAttributeSetThemeStyle,
        Theme.LIGHT to lightAttributeSetThemeStyle
    )

    object ThemeColors {
        val Accent = Color(216, 101, 51)
    }
}
