import gqlpy


class GQLSubQuery(object):
    field       = None  # type: gqlpy.GQLField
    name        = ''    # type: str
    description = ''    # type: str
    max_depth   = 4     # type: int

    def __init__(self, field, max_depth=5):
        self.field        = field
        self.name         = field.name
        self.max_depth    = max_depth - 1

    def __repr__(self):
        self.print_query()

    @staticmethod
    def _indent(indent):
        """Generates characters that should be used for Space and Newline, depending on request indentation level.

        If indent > 0, space is preserved and new lines are started with 'indent' number of spaces.
        If indent = 0, space is preserved, but new lines are removed
        If indent = None, both space and newlines are trimmed.
        """
        NEWLINE = '\n' if indent else ''
        PADDING = ' ' * (indent) if indent else ''
        SPACE   = ' '  if (indent is not None) else ''

        return SPACE, NEWLINE, PADDING

    def print_query(self, indent=2):
        """Generate a string representation.

        'indent' parameter defines number of space characters to use for indentation. Special values:
        'indent=0'    generates minimized query (oneliner without comments).
        'indent=None' generates super-optimized query where spaces are omitted as much as possible
        """
        # whitespace characters collapse when query gets minimized
        SPACE, NEWLINE, PADDING = self._indent(indent)

        arguments = (',' + SPACE).join([str(x) for x in self.field.args])

        first_line = ''.join((
            self.name,
            "({arguments})".format(arguments=arguments) if arguments else "",
            (SPACE + "{" + NEWLINE) if not self.field.type.kind.is_leaf else NEWLINE
        ))

        middle_lines = ''
        if self.max_depth:
            for field in self.field.type.fields:
                subquery = GQLSubQuery(field, max_depth=self.max_depth)
                middle_lines += PADDING + ' ' * 4 + NEWLINE.join(subquery.print_query(indent + 4).splitlines()) + NEWLINE
        else:
            # Max recursion depth reached
            middle_lines = PADDING + ' ' * 4 + '!!! MAX RECURSION DEPTH REACHED !!!' + NEWLINE

        last_line = PADDING + '}' + NEWLINE if not self.field.type.kind.is_leaf else ""

        if indent:
            if self.description:
                description_line = gqlpy.utils.format_comment(self.description) + NEWLINE
            else:
                description_line = ''
            return description_line + first_line + middle_lines + last_line
        else:
            return first_line + middle_lines + last_line
