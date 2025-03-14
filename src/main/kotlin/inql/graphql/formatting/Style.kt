package inql.graphql.formatting

import burp.Burp
import burp.api.montoya.ui.Theme
import java.awt.Color

class Style {
    companion object {
        const val CLASS_STRING = "string"
        const val CLASS_NUMBER = "number"
        const val CLASS_COMMENT = "comment"
        const val CLASS_SYMBOL = "symbol"
        const val CLASS_FIELD = "field"
        const val CLASS_TYPE = "type"
        const val CLASS_ARGUMENT = "argument"
        const val CLASS_KEYWORD = "keyword"
        const val CLASS_FRAGMENT = "fragment"
        const val CLASS_VALUE = "value"
        const val CLASS_OBJECT = "object"
        const val CLASS_VARIABLE = "variable"
        const val CLASS_OPNAME = "opName"
        const val CLASS_OPERATION = "operation"
        const val CLASS_ALIAS = "alias"
        const val CLASS_DIRECTIVE = "directive"

        val CLASSES = listOf(
            CLASS_STRING,
            CLASS_NUMBER,
            CLASS_COMMENT,
            CLASS_SYMBOL,
            CLASS_FIELD,
            CLASS_TYPE,
            CLASS_ARGUMENT,
            CLASS_KEYWORD,
            CLASS_FRAGMENT,
            CLASS_VALUE,
            CLASS_OBJECT,
            CLASS_VARIABLE,
            CLASS_OPNAME,
            CLASS_OPERATION,
            CLASS_ALIAS,
            CLASS_DIRECTIVE,
        )

        fun getClass(t: Token): String {
            return when (t.type) {
                Token.Type.STRING -> CLASS_STRING
                Token.Type.NUMBER -> CLASS_NUMBER
                Token.Type.COMMENT -> CLASS_COMMENT
                Token.Type.PUNCTUATOR -> CLASS_SYMBOL
                Token.Type.EMPTY -> ""
                Token.Type.NAME -> {
                    when (t.subtype) {
                        Token.Subtype.FIELD_NAME -> CLASS_FIELD
                        Token.Subtype.TYPE -> CLASS_TYPE
                        Token.Subtype.ARGUMENT_NAME -> CLASS_ARGUMENT
                        Token.Subtype.KEYWORD -> CLASS_KEYWORD
                        Token.Subtype.FRAGMENT_NAME -> CLASS_FRAGMENT
                        Token.Subtype.VALUE -> CLASS_VALUE
                        Token.Subtype.OBJECT_NAME -> CLASS_OBJECT
                        Token.Subtype.VARIABLE_NAME -> CLASS_VARIABLE
                        Token.Subtype.OPERATION_NAME -> CLASS_OPNAME
                        Token.Subtype.OPERATION_TYPE -> CLASS_OPERATION
                        Token.Subtype.ALIAS_NAME -> CLASS_ALIAS
                        Token.Subtype.DIRECTIVE_NAME -> CLASS_DIRECTIVE
                        Token.Subtype.NONE -> ""
                    }
                }
            }
        }

        val darkThemeStyle = Style().setColors(
            mapOf(
                "string" to "#92c563",
                "number" to "#f99b56",
                "comment" to "#C0C0C0",
                "symbol" to "",
                "field" to "#e9bf63",
                "type" to "#75b5df",
                "argument" to "#90EE90",
                "keyword" to "white",
                "fragment" to "#FF8C00",
                "value" to "#f99b56",
                "object" to "#e9bf63",
                "variable" to "#f792da",
                "opName" to "#FF8C00",
                "operation" to "white",
                "alias" to "#24d6c7",
                "directive" to "#FFEF9F",
            ),
        )

        val lightThemeStyle = Style().setColors(
            mapOf(
                "string" to "#1b8d1a",
                "number" to "#1c1cff",
                "comment" to "#C0C0C0",
                "symbol" to "",
                "field" to "#CB9921",
                "type" to "#209FF3",
                "argument" to "#388E38",
                "keyword" to "#202020",
                "fragment" to "#FF830B",
                "value" to "#1c1cff",
                "object" to "#388E38",
                "variable" to "#F34BC3",
                "opName" to "#FF830B",
                "operation" to "#202020",
                "alias" to "#1CA89D",
                "directive" to "#a5b125",
            ),
        )

        val darkAttributeSetThemeStyle = mapOf(
                "string" to Color(146, 197, 99),
                "number" to Color(249, 155, 86),
                "comment" to Color(192, 192, 192),
                "symbol" to Color(32,32,32),
                "field" to Color(233, 191, 99),
                "type" to Color(117, 181, 223),
                "argument" to Color(144, 238, 144),
                "keyword" to Color(255, 255, 255),
                "fragment" to Color(255, 140, 0),
                "value" to Color(249, 155, 86),
                "object" to Color(233, 191, 99),
                "variable" to Color(247, 146, 218),
                "opName" to Color(255, 140, 0),
                "operation" to Color(255, 255, 255),
                "alias" to Color(36, 214, 199),
                "directive" to Color(255, 239, 159),
            )

        val lightAttributeSetThemeStyle = mapOf(
            "string" to Color(27, 141, 26),
            "number" to Color(28, 28, 255),
            "comment" to Color(192, 192, 192),
            "symbol" to Color(32,32,32),
            "field" to Color(203, 153, 33),
            "type" to Color(32, 159, 243),
            "argument" to Color(56, 142, 56),
            "keyword" to Color(32, 32, 32),
            "fragment" to Color(255, 131, 11),
            "value" to Color(28, 28, 255),
            "object" to Color(56, 142, 56),
            "variable" to Color(243, 75, 195),
            "opName" to Color(255, 131, 11),
            "operation" to Color(32, 32, 32),
            "alias" to Color(28, 168, 157),
            "directive" to Color(165, 177, 37),
        )

        fun getStyleCSS(): String {
            return if (Burp.Montoya.userInterface().currentTheme() == Theme.DARK) {
                darkThemeStyle.getCSS()
            } else {
                lightThemeStyle.getCSS()
            }
        }
    }

    private val cssProperties: HashMap<String, HashMap<String, String>> =
        HashMap<String, HashMap<String, String>>().also {
            CLASSES.forEach { className ->
                it[className] = HashMap()
            }
        }

    fun setProperty(classname: String, property: String, value: String): Style {
        if (!CLASSES.contains(classname)) {
            throw Exception("Invalid class name: $classname")
        }

        if (Regex("[^a-z-]]").matches(property)) {
            throw Exception("Property with invalid characters: $property")
        }

        if (Regex("[^A-Za-z0-9#-]]").matches(value)) {
            throw Exception("Value with invalid characters: $value")
        }

        cssProperties[classname]!![property.trim()] = value.trim()
        return this
    }

    fun setColor(classname: String, color: String): Style {
        this.setProperty(classname, "color", color)
        return this
    }

    fun setColors(colorMap: Map<String, String>): Style {
        colorMap.forEach {
            this.setProperty(it.key, "color", it.value)
        }
        return this
    }

    fun getCSS(): String {
        val css = StringBuilder()
        css.appendLine("body, span, pre, code { white-space: pre; }")
        for ((classname, properties) in this.cssProperties) {
            css.appendLine(".$classname{ ${properties.map { (name, value) -> "$name: $value" }.joinToString("; ")} }")
        }
        return css.toString()
    }
}
