package inql.scanner.scanresults

abstract class ScanResultElement(val name: String) {
    abstract fun content(): String
}