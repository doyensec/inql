package inql.attackvector.tests

import inql.attackvector.DetailsFormat
import inql.attackvector.GraphqlProbe
import inql.attackvector.ScanContext
import inql.attackvector.ScanHttpClient
import inql.attackvector.ScannerTest
import inql.attackvector.TestEvidence
import inql.attackvector.TestResult
import inql.attackvector.TestStatus
import inql.fingerprinter.EngineProbes
import inql.fingerprinter.ThreatMatrix
import inql.fingerprinter.ThreatMatrixRenderer

object BackendFingerprintingTest : ScannerTest {
    override val id = "backend_fingerprint"
    override val name = "Backend Engine Fingerprinting"
    override val description = "Identifies the GraphQL server engine from characteristic probe responses."

    override suspend fun run(context: ScanContext): TestResult {
        val probes = EngineProbes(context.client)
        if (!probes.isGraphQLServer()) {
            val request = context.client.lastRequest
            val response = context.client.lastResponse
            if (request != null && response != null) {
                GraphqlProbe.classifyHttpFailure(name, ScanHttpClient.HttpExchange(request, response))?.let { return it }
            }
            val evidence = if (request != null && response != null) TestEvidence(request, response) else null
            return TestResult(
                name,
                TestStatus.UNCERTAIN,
                "Target did not respond like a GraphQL server during fingerprinting.",
                evidence,
            )
        }

        val engineKey = probes.detectEngine()
        return if (engineKey != null) {
            val engine = ThreatMatrix.engine(engineKey)
            if (engine != null) {
                TestResult(
                    name,
                    TestStatus.IDENTIFIED,
                    ThreatMatrixRenderer.render(engine),
                    detailsFormat = DetailsFormat.HTML,
                    statusLabel = engine.name,
                )
            } else {
                TestResult(
                    name,
                    TestStatus.IDENTIFIED,
                    "Identified GraphQL engine: $engineKey",
                    statusLabel = engineKey,
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
