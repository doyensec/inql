package inql.attackvector.tests

import inql.attackvector.DetailsFormat
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import inql.fingerprinter.EngineFingerprintReport
import inql.fingerprinter.EngineProbes
import inql.fingerprinter.Helpers

object BackendFingerprintingTest : ScannerTest {
    override val id = "backend_fingerprint"
    override val name = "Backend Engine Fingerprinting"
    override val description = "Identifies the GraphQL server engine from characteristic probe responses."

    override suspend fun run(context: ScanContext): TestResult {
        val probes = EngineProbes(context.client)
        if (!probes.isGraphQLServer()) {
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Target did not respond like a GraphQL server during fingerprinting.",
            )
        }

        val engineKey = probes.detectEngine()
        return if (engineKey != null) {
            val engineName = Helpers.engines[engineKey]?.name ?: engineKey
            val html = EngineFingerprintReport.htmlForEngine(engineKey)
            if (html != null) {
                TestResult(
                    name,
                    TestStatus.IDENTIFIED,
                    html,
                    detailsFormat = DetailsFormat.HTML,
                    statusLabel = engineName,
                )
            } else {
                TestResult(
                    name,
                    TestStatus.IDENTIFIED,
                    "Identified GraphQL engine: $engineName",
                    statusLabel = engineName,
                )
            }
        } else {
            TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Server responds to GraphQL but engine could not be fingerprinted.",
            )
        }
    }
}
