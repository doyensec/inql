package inql.graphql.scanners

object PathEnumerationExport {
    fun toCsv(paths: List<PathResult>): String {
        return buildString {
            appendLine("Depth,Entrypoint,Path")
            for (path in paths) {
                appendLine(
                    listOf(
                        path.depth.toString(),
                        escapeCsv(path.entrypoint),
                        escapeCsv(path.pathPreview()),
                    ).joinToString(","),
                )
            }
        }.trimEnd()
    }

    private fun escapeCsv(value: String): String {
        if (value.none { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            return value
        }
        return "\"${value.replace("\"", "\"\"")}\""
    }
}
