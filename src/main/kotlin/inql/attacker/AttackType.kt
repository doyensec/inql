package inql.attacker

enum class BatchMode(val label: String) {
    ALIAS("Alias Batching"),
    ARRAY("Array Batching"),
}

enum class IntruderAttackType(val label: String, val description: String) {
    SNIPER(
        "Sniper attack",
        "Inserts each payload into each variable one at a time, using a single payload set.",
    ),
    BATTERING_RAM(
        "Battering ram attack",
        "Places the same payload into all variables at once, using a single payload set.",
    ),
    PITCHFORK(
        "Pitchfork attack",
        "Uses a separate payload set for each variable and steps through all sets in parallel.",
    ),
    CLUSTER_BOMB(
        "Cluster bomb attack",
        "Uses a separate payload set for each variable and tries every combination of their payloads.",
    ),
    ;

    companion object {
        fun fromLabel(label: String): IntruderAttackType {
            return entries.first { it.label == label }
        }
    }
}

enum class BatchVariableKind {
    VARIABLE,
    ARGUMENT,
}

data class BatchVariable(
    val path: List<String>,
    val type: String? = null,
    val kind: BatchVariableKind = BatchVariableKind.VARIABLE,
    val graphqlVariable: String = path.first(),
    val jsonPath: List<String> = path,
) {
    val key: String get() = BatchVariableCollector.joinPath(path)
    val graphqlName: String get() = graphqlVariable
    val jsonKey: String get() = BatchVariableCollector.joinPath(jsonPath)
    val displayName: String
        get() = if (kind == BatchVariableKind.ARGUMENT) key else "$$key"
}

/** A payload set: where the payloads come from and which JSON type they are sent as. */
data class PayloadSetConfig(
    val source: PayloadSource,
    val valueType: PayloadValueType = PayloadValueType.AUTO,
)

data class BatchAttackConfig(
    val mode: BatchMode,
    val attackType: IntruderAttackType,
    val selectedVariables: List<String>,
    val sharedSource: PayloadSetConfig?,
    val perVariableSources: Map<String, PayloadSetConfig>,
    /** Maximum number of batched items per HTTP request; 0 sends everything in one request. */
    val batchSize: Int = 0,
) {
    fun usesSharedPayload(): Boolean {
        return selectedVariables.size < 2 ||
            attackType == IntruderAttackType.SNIPER ||
            attackType == IntruderAttackType.BATTERING_RAM
    }
}
