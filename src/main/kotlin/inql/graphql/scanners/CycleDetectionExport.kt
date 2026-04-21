package inql.graphql.scanners

object CycleDetectionExport {
    fun formatAll(cycles: List<CycleResult>): String {
        if (cycles.isEmpty()) return "<no cycles detected>"
        return buildString {
            cycles.forEachIndexed { index, c ->
                appendLine("--- Cycle ${index + 1} ---")
                appendLine("Operation: ${c.operationType.name.lowercase()}")
                appendLine("Entrypoint: ${c.entrypoint}")
                appendLine("Depth: ${c.depth}")
                appendLine("Path: ${c.pathPreview()}")
                appendLine()
            }
        }.trimEnd()
    }
}
