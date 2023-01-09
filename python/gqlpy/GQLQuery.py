import gqlpy


class GQLQuery:
    type    = None    # type: gqlpy.GQLType
    operation = ''    # type: str
    name   = ''       # type: str
    description = ''  # type: str
    fields = None     # type: List[gqlpy.GQLField]

    def __init__(self, gqltype, operation='query', name='', fields=None):
        self.fields = fields if fields else self.type.fields
        self.operation = operation
        self.name = name
        self.type = gqltype

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

        first_line = ''.join((
            'query',
            (' ' + self.name) if self.name else '',
            SPACE + '{' + NEWLINE
        ))

        middle_lines = ""
        for field in self.fields:
            subquery = gqlpy.GQLSubQuery(field)
            middle_lines += PADDING + NEWLINE.join(subquery.print_query(indent + 2).splitlines()) + NEWLINE

        last_line = '}' + NEWLINE if not self.type.kind.is_leaf else ""

        if indent:
            if self.description:
                description_line = gqlpy.utils.format_comment(self.description) + NEWLINE
            else:
                description_line = ''
            return description_line + first_line + middle_lines + last_line
        else:
            return first_line + middle_lines + last_line
