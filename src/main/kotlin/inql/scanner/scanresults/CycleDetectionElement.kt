package inql.scanner.scanresults

import inql.Config
import inql.graphql.GQLSchema
import inql.graphql.scanners.CycleResult
import inql.graphql.scanners.CyclesScanner
import inql.scanner.ScanResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext

class CycleDetectionEntry(
    val scanResult: ScanResult,
    val gqlSchema: GQLSchema,
) {
    var payload: CycleDetectionPayload = CycleDetectionPayload.Loading
    private var loadStarted = false

    fun ensureLoaded(onUpdate: () -> Unit) {
        if (payload !is CycleDetectionPayload.Loading) return
        if (loadStarted) return
        loadStarted = true

        CoroutineScope(Dispatchers.Default).launch {
            val result = try {
                val config = Config.getInstance()
                val maxDepth = config.getInt("report.cycles.depth")!!
                val maxCycles = config.getInt("report.cycles.max")!!
                val scanner = CyclesScanner(gqlSchema, maxDepth, maxCycles)
                scanner.detect()
                CycleDetectionPayload.Ready(scanner.cycleResults(), scanResult)
            } catch (e: Exception) {
                CycleDetectionPayload.Ready(emptyList(), scanResult)
            }

            withContext(Dispatchers.Swing) {
                payload = result
                onUpdate()
            }
        }
    }
}

sealed class CycleDetectionPayload {
    object Loading : CycleDetectionPayload()

    class Ready(
        val cycles: List<CycleResult>,
        val scanResult: ScanResult,
    ) : CycleDetectionPayload()
}
