package inql.scanner.scanresults

import inql.graphql.scanners.CycleDetectionExport
import inql.graphql.scanners.CycleResult
import inql.scanner.ScanResult

sealed class CycleDetectionPayload : ScanResultElement("Cycle Detection") {
    object Loading : CycleDetectionPayload() {
        override fun content(): String = ""
    }

    class Ready(
        val cycles: List<CycleResult>,
        val scanResult: ScanResult,
    ) : CycleDetectionPayload() {
        override fun content(): String = CycleDetectionExport.formatAll(cycles)
    }
}
