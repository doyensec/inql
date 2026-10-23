package inql.fingerprinter

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import inql.utils.ResourceFileReader

/**
 * Default security posture of known GraphQL engines, bundled in resources/threat-matrix.json.
 *
 * The data was adapted from the GraphQL Threat Matrix (https://github.com/nicholasaleks/graphql-threat-matrix)
 * and is maintained in InQL from now on; it is never fetched at runtime.
 */
object ThreatMatrix {
    enum class FeatureStatus(val label: String) {
        @SerializedName("enabled") ENABLED("Enabled"),
        @SerializedName("disabled") DISABLED("Disabled"),
        @SerializedName("not_supported") NOT_SUPPORTED("Not supported"),
        @SerializedName("unknown") UNKNOWN("Unknown"),
    }

    /** Which state of a feature exposes attack surface. */
    enum class RiskWhen {
        @SerializedName("enabled") ENABLED,

        /** Protection is disabled by default or not supported at all. */
        @SerializedName("absent") ABSENT,
    }

    data class FeatureDefinition(val label: String, val riskWhen: RiskWhen, val risk: String)

    data class FeatureState(val status: FeatureStatus, val note: String?)

    data class Vulnerability(val id: String, val url: String, val description: String)

    data class Engine(
        val name: String,
        val language: List<String>,
        val source: String,
        val docs: String,
        val features: Map<String, FeatureState>,
        val vulnerabilities: List<Vulnerability>,
    )

    private data class Data(val features: Map<String, FeatureDefinition>, val engines: Map<String, Engine>)

    private val data: Data by lazy {
        Gson().fromJson(ResourceFileReader.readFile("threat-matrix.json"), Data::class.java)
    }

    /** Feature definitions, in the order they should be displayed. */
    val features: Map<String, FeatureDefinition> get() = data.features

    /** Looks up an engine by the key returned from [EngineProbes.detectEngine]. */
    fun engine(key: String): Engine? = data.engines[key]

    /** Returns null when the status is unknown, otherwise whether it exposes attack surface. */
    fun isRisky(definition: FeatureDefinition, status: FeatureStatus): Boolean? = when (status) {
        FeatureStatus.UNKNOWN -> null
        FeatureStatus.ENABLED -> definition.riskWhen == RiskWhen.ENABLED
        FeatureStatus.DISABLED, FeatureStatus.NOT_SUPPORTED -> definition.riskWhen == RiskWhen.ABSENT
    }
}
