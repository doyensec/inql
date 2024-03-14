package inql.scanner.scanresults

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.swing.tree.DefaultMutableTreeNode
import burp.api.montoya.core.ByteArray

sealed class ScanResult {
    data class GraphQL(val content: String): ScanResult()
    data class Raw(val content: ByteArray): ScanResult() {
        constructor(content: String): this(ByteArray.byteArray(content))
    }
}

/*
 * This class is used to create a tree node that loads its content lazily.
 */

class ScanResultsTreeNode(val label: String,
                            private val loadContentAsync: (suspend() -> ScanResult)? = null):
    DefaultMutableTreeNode(label) {

    suspend fun getContent(): ScanResult? =
        loadContentAsync?.invoke()
}