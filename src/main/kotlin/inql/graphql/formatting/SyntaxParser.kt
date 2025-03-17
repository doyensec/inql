package inql.graphql.formatting

import inql.Logger
import java.util.*

/*
 GraphQL ignores whitespace (outside strings and comments) and commas
 Tokens:
   Punctuator      !	$	&	(	)	...	:	=	@	[	]	{	|	}
   Name            starts with letter, continues letters, digits, _
   IntValue
   FloatValue
   StringValue     but """ starts a block string
 */
class SyntaxParser private constructor(val originalTokens: LinkedList<Token>, val fixIntrospection: Boolean = false) {
    companion object {
        fun parse(tokens: List<Token>, fixIntrospection: Boolean = false): List<Token> {
            return SyntaxParser(LinkedList(tokens), fixIntrospection).parse()
        }
    }

    /* Get only tokens with syntactic relevance */
    val tokens = originalTokens.filter { t -> t.type != Token.Type.COMMENT && t.text != "," }

    private var idx = 0

    private val current: Token
        get() = this.tokens[this.idx]

    private val next: Token
        get() = this.tokens[this.idx + 1]

    private fun parse(): List<Token> {
        try {
            document()
        } catch (e: Exception) {
            Logger.error("Error while parsing GraphQL")
            Logger.error((e.stackTraceToString()))
        }
        return this.originalTokens.filter { it.type != Token.Type.EMPTY }
    }

    private fun consume() {
        idx++
    }

    private fun consumeText(text: String) {
        if (current.text != text) throw unexpectedToken(text)
        consume()
    }

    private fun unexpectedToken(expected: String): Exception {
        return Exception("Unexpected token: ${current.text} with type ${current.type}, was expecting '$expected'")
    }

    private fun delete() {
        this.tokens[this.idx].type = Token.Type.EMPTY
        this.tokens[this.idx].text = ""
    }

    private fun document() {
        /*
        Document:
        Definition[list]

        Definition:
            ExecutableDefinition
            TypeSystemDefinition
            TypeSystemExtension

        ExecutableDefinition:
            OperationDefinition
            FragmentDefinition
         */
        while (this.idx < this.tokens.size) {
            definition()
        }
    }

    private fun definition() {
        executableDefinition()
    }

    private fun executableDefinition() {
        when (current.text) {
            "fragment" -> fragmentDefinition()
            "{", "query", "mutation", "subscription" -> operationDefinition()
            else -> throw unexpectedToken("operationDefinition or fragmentDefinition")
        }
    }

    private fun operationDefinition() {
        // OperationType Name[opt] VariableDefinitions[opt] Directives[opt] SelectionSet
        // SelectionSet

        if (current.text == "{") {
            // Query shorthand
            selectionSet()
            return
        }

        // OperationType
        if (!setOf("query", "mutation", "subscription").contains(current.text)) throw unexpectedToken("OPERATION_TYPE")
        this.current.subtype = Token.Subtype.OPERATION_TYPE
        consume()

        // Name[opt]
        if (current.type == Token.Type.NAME) {
            current.subtype = Token.Subtype.OPERATION_NAME
            consume()
        }

        // VariableDefinitions[opt]
        if (current.text == "(") {
            variableDefinitions()
        }

        if (current.text == "@") {
            directives()
        }

        selectionSet()
    }

    private fun fragmentName() {
        // Name but not "on"
        if (current.type == Token.Type.NAME && current.text != "on") {
            current.subtype = Token.Subtype.FRAGMENT_NAME
            consume()
        } else {
            throw unexpectedToken("FRAGMENT NAME")
        }
    }

    private fun typeCondition() {
        // on NamedType
        if (current.text != "on") throw unexpectedToken("on")
        this.current.subtype = Token.Subtype.KEYWORD
        consume()

        if (this.current.type != Token.Type.NAME) throw unexpectedToken("NamedType")
        this.current.subtype = Token.Subtype.TYPE
        consume()
    }

    private fun fragmentDefinition() {
        if (current.text != "fragment") throw unexpectedToken("fragment")
        this.current.subtype = Token.Subtype.KEYWORD
        consume()

        fragmentName()
        typeCondition()
        if (current.text == "@") {
            directives()
        }
        selectionSet()
    }

    private fun directives() {
        while (current.text == "@") {
            if (current.text != "@") throw unexpectedToken("@")
            this.delete()
            this.consume()
            if (current.type != Token.Type.NAME) unexpectedToken("DIRECTIVE NAME")
            current.subtype = Token.Subtype.DIRECTIVE_NAME
            current.text = "@${current.text}"
            consume()
            if (current.text == "(") {
                arguments()
            }
        }
    }

    private fun arguments() {
        consumeText("(")
        while (current.text != ")") {
            if (current.type != Token.Type.NAME) throw unexpectedToken("ARGUMENT NAME")
            current.subtype = Token.Subtype.ARGUMENT_NAME
            consume()
            consumeText(":")
            value()
        }
        consumeText(")")
    }

    private fun argumentsDefinition() {
        consumeText("(")
        while (current.text != ")") {
            if (current.type != Token.Type.NAME) throw unexpectedToken("ARGUMENT NAME")
            current.subtype = Token.Subtype.ARGUMENT_NAME
            consume()
            consumeText(":")
            // Type
            type()
            // DefaultValue[opt]
            if (current.text == "=") {
                consume() // "="
                value()
            }
            if (current.text == "@") {
                directives()
            }
        }
        consumeText(")")
    }

    private fun variableName() {
        /*
        $ Name
         */
        if (current.text == "$" && next.type == Token.Type.NAME) {
            this.delete()
            this.consume()
            this.current.text = "\$${current.text}"
            this.current.subtype = Token.Subtype.VARIABLE_NAME
            consume()
        } else {
            throw unexpectedToken("VARIABLE NAME")
        }
    }

    private fun type() {
        /*
        NamedType
        ListType
        NamedType!
        ListType!

        NamedType = Name
        ListType = [ Type...]
         */
        if (this.current.type == Token.Type.NAME) {
            // Named Type
            this.current.subtype = Token.Subtype.TYPE
            if (next.type == Token.Type.PUNCTUATOR && next.text == "!") {
                // NotNullType
                this.current.text = "${this.current.text}!"
                this.consume()
                this.delete()
            }
            consume()
        } else if (this.current.type == Token.Type.PUNCTUATOR && this.current.text == "[") {
            // ListType
            consumeText("[")
            while (this.current.text != "]") type()
            consumeText("]")
            if (current.type == Token.Type.PUNCTUATOR && current.text == "!") {
                consumeText("!")
            }
        }
    }

    private fun variableDefinitions() {
        /*
        Variable : Type DefaultValue[opt]
         */
        consumeText("(")
        while (current.text != ")") {
            // Variable
            variableName()
            consumeText(":")
            // Type
            type()
            // DefaultValue[opt]
            if (current.text == "=") {
                consume() // "="
                value()
            }
        }
        consumeText(")")
    }

    private fun selectionSet() {
        consumeText("{")
        while (current.text != "}") {
            if (current.text == "...") {
                fragmentSpreadOrInlineFragment()
            } else {
                field()
            }
        }
        consumeText("}")
    }

    private fun alias() {
        if (current.type != Token.Type.NAME) throw unexpectedToken("ALIAS NAME")
        current.subtype = Token.Subtype.ALIAS_NAME
        consume()
        consumeText(":")
    }

    private fun field() {
        if (idx + 2 < tokens.size &&
            current.type == Token.Type.NAME &&
            next.text == ":" &&
            tokens[idx + 2].type == Token.Type.NAME
        ) {
            alias()
        }
        if (current.type != Token.Type.NAME) throw unexpectedToken("FIELD NAME")
        current.subtype = Token.Subtype.FIELD_NAME
        consume()

        if (current.text == "(") {
            if (this.fixIntrospection) {
                argumentsDefinition()
            } else {
                arguments()
            }
        }
        if (current.text == "@") directives()
        if (current.text == "{") selectionSet()
    }

    private fun fragmentSpreadOrInlineFragment() {
        if (current.text == "...") {
            if (next.type == Token.Type.NAME && next.text != "on") {
                fragmentSpread()
            } else if (next.text == "on" || next.text == "@" || next.text == "{") {
                inlineFragment()
            } else {
                consume()
                throw unexpectedToken("fragmentSpread or inlineFragment")
            }
        } else {
            throw unexpectedToken("...")
        }
    }

    private fun inlineFragment() {
        consumeText("...")
        if (current.text == "on") typeCondition()
        if (current.text == "@") directives()
        selectionSet()
    }

    private fun fragmentSpread() {
        consumeText("...")
        fragmentName()
        if (current.text == "@") {
            directives()
        }
    }

    private fun objectValue() {
        consumeText("{")
        while (this.current.text != "}") {
            // Name
            if (current.type != Token.Type.NAME) throw unexpectedToken("Object Name")
            this.current.subtype = Token.Subtype.OBJECT_NAME
            consume()
            consumeText(":")
            value()
        }
        consumeText("}")
    }

    private fun value() {
        /*
        Variable
        IntValue
        FloatValue
        StringValue
        BooleanValue
        NullValue
        EnumValue
        ListValue
        ObjectValue
         */
        when (current.type) {
            Token.Type.NUMBER, Token.Type.STRING -> {
                this.current.subtype = Token.Subtype.VALUE
                consume()
            }

            Token.Type.NAME -> {
                if (next.text == "!") {
                    // FIXME: Apparently this is actually a type, not a value.
                    //  For some reason queries generated from introspection we have types instead of values
                    type()
                    return
                }
                // Boolean, Null or Enum
                this.current.subtype = Token.Subtype.VALUE
                consume()
            }

            Token.Type.PUNCTUATOR -> {
                when (current.text) {
                    "$" -> {
                        variableName()
                    }

                    "[" -> {
                        consumeText("[")
                        while (current.text != "]") value()
                        consumeText("]")
                        if (current.text == "!") consume() // FIXME: Temporary fix for the type <-> value switcheroo
                    }

                    "{" -> {
                        objectValue()
                    }

                    else -> {
                        throw unexpectedToken("$, [, or {")
                    }
                }
            }

            else -> {
                throw unexpectedToken("VALUE")
            }
        }
    }
}
