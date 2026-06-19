package inql.attackvector

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import inql.bruteforcer.ThrottledClient
import kotlinx.coroutines.ensureActive

data class TestEvidence(
    val request: HttpRequest,
    val response: HttpResponse,
) {
    val statusCode: Int get() = response.statusCode().toInt()
}

enum class TestStatus(val label: String) {
    PENDING("Pending"),
    RUNNING("Running"),
    CONFIRMED("Confirmed"),
    NOT_VULNERABLE("Not Vulnerable"),
    UNCERTAIN("Uncertain"),
    CANCELLED("Cancelled"),
}

enum class DetailsFormat {
    PLAIN,
    MARKDOWN,
    HTML,
}

data class TestResult(
    val name: String,
    val status: TestStatus,
    val details: String,
    val evidence: TestEvidence? = null,
    val detailsFormat: DetailsFormat = DetailsFormat.PLAIN,
)

data class ScanConfig(
    val maxDepth: Int,
    val maxBatchSize: Int,
    val maxComplexity: Int,
    val enabledTests: Set<String>,
)

data class ScanContext(
    val client: ThrottledClient,
    val request: HttpRequest,
    val config: ScanConfig,
    val http: ScanHttpClient,
) {
    suspend fun ensureActive() {
        kotlin.coroutines.coroutineContext.ensureActive()
    }
}

interface ScannerTest {
    val id: String
    val name: String

    fun isEnabled(config: ScanConfig): Boolean = id in config.enabledTests

    suspend fun run(context: ScanContext): TestResult
}
