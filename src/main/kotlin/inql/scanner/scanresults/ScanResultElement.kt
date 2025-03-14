package inql.scanner.scanresults

abstract class ScanResultElement(val name: String) {
    public abstract fun content(): String
}