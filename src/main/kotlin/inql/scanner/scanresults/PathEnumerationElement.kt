package inql.scanner.scanresults

import inql.graphql.GQLSchema
import inql.graphql.scanners.PathResult
import inql.scanner.ScanResult

data class PathEnumerationState(
    val targetText: String = "",
    val selectedTargetLabel: String? = null,
    val maxDepth: Int = 5,
    val includeQuery: Boolean = true,
    val includeMutation: Boolean = true,
    val includeSubscription: Boolean = true,
    val paths: List<PathResult> = emptyList(),
    val statusText: String = "Pick a type or field from the suggestions, then click Search.",
    val tablePage: Int = 0,
    val tablePageSize: Int = 50,
    val sortColumn: Int = 0,
    val sortAscending: Boolean = true,
)

class PathEnumerationEntry(
    val scanResult: ScanResult,
    val gqlSchema: GQLSchema,
) {
    var state: PathEnumerationState = PathEnumerationState()
}
