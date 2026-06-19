package inql.attackvector

import inql.attackvector.tests.BackendFingerprintingTest
import inql.attackvector.tests.BatchAliasLimitTest
import inql.attackvector.tests.BatchArrayLimitTest
import inql.attackvector.tests.FederationSdlTest
import inql.attackvector.tests.FieldSuggestionTest
import inql.attackvector.tests.GetMutationSupportTest
import inql.attackvector.tests.GetQuerySupportTest
import inql.attackvector.tests.GraphQLInterfacesTest
import inql.attackvector.tests.IntrospectionTest
import inql.attackvector.tests.PostBasedCsrfTest
import inql.attackvector.tests.QueryComplexityLimitTest
import inql.attackvector.tests.QueryDepthLimitTest

object AttackVectorTestRegistry {
    val allTests: List<ScannerTest> = listOf(
        IntrospectionTest,
        FederationSdlTest,
        QueryDepthLimitTest,
        QueryComplexityLimitTest,
        BatchArrayLimitTest,
        BatchAliasLimitTest,
        FieldSuggestionTest,
        BackendFingerprintingTest,
        GraphQLInterfacesTest,
        GetQuerySupportTest,
        GetMutationSupportTest,
        PostBasedCsrfTest,
    )

    val allTestIds: Set<String> = allTests.map { it.id }.toSet()
}
