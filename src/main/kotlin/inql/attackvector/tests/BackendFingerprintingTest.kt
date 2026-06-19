package inql.attackvector.tests

import inql.attackvector.DetailsFormat
import inql.attackvector.ScanContext
import inql.attackvector.ScannerTest
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import inql.fingerprinter.EngineFingerprintReport
import inql.fingerprinter.EngineProbes

object BackendFingerprintingTest : ScannerTest {
    override val id = "backend_fingerprint"
    override val name = "Backend Fingerprinting"

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
            val html = EngineFingerprintReport.htmlForEngine(engineKey)
            if (html != null) {
                TestResult(
                    name,
                    TestStatus.CONFIRMED,
                    html,
                    detailsFormat = DetailsFormat.HTML,
                )
            } else {
                TestResult(
                    name,
                    TestStatus.CONFIRMED,
                    "Identified GraphQL engine key: $engineKey",
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
