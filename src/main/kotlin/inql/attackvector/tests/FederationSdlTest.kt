package inql.attackvector.tests

import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus

object FederationSdlTest : ScannerTest {
    override val id = "federation_sdl"
    override val name = "Apollo Federation SDL"
    override val description = "Attempts to fetch the Apollo Federation _service { sdl } schema document."

    override suspend fun run(context: ScanContext): TestResult {
        val exchange = context.http.sendFederationSdlExchange()
        val evidence = exchange.toEvidence()
        val sdl = parseFederationSdl(exchange.body)

        return when {
            sdl != null && sdl.contains("type") -> TestResult(
                name,
                TestStatus.VULNERABLE,
                "Federation _service { sdl } returned a non-empty SDL document.",
                evidence,
            )
            sdl != null -> TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Federation SDL endpoint responded but the SDL content could not be verified.",
                evidence,
            )
            exchange.asJsonOrNull()?.has("errors") == true -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Federation SDL query rejected or unavailable.",
                evidence,
            )
            else -> TestResult(
                name,
                TestStatus.NOT_VULNERABLE,
                "Federation SDL query rejected or unavailable (HTTP ${exchange.statusCode}).",
                evidence,
            )
        }
    }

    private fun parseFederationSdl(body: String): String? {
        if (body.isBlank()) return null
        return try {
            val data = org.json.JSONObject(body).optJSONObject("data") ?: return null
            val service = data.optJSONObject("_service") ?: return null
            service.optString("sdl").takeIf { it.isNotBlank() }
        } catch (_: Exception) {
            null
        }
    }
}
