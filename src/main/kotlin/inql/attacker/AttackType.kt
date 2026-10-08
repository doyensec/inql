package inql.attacker

enum class BatchMode(val label: String) {
    ALIAS("Alias Batching"),
    ARRAY("Array Batching"),
    ;

    companion object {
        /** Reads a mode saved in the project file; accepts enum names and labels, defaulting to [ALIAS]. */
        fun fromStored(value: String?): BatchMode {
            return entries.firstOrNull { it.name == value || it.label == value } ?: ALIAS
        }
    }
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

    /** True if all variables share one payload set. */
    val usesSharedPayloadSet: Boolean get() = this == SNIPER || this == BATTERING_RAM

    /** With fewer than two variables every attack type behaves like Sniper. */
    fun effectiveFor(variableCount: Int): IntruderAttackType = if (variableCount < 2) SNIPER else this

    companion object {
        fun fromLabel(label: String): IntruderAttackType {
            return entries.first { it.label == label }
        }
    }
}

enum class BatchVariableKind {
    /** A GraphQL variable, or a value nested in one; [BatchVariable.path] is its path in the variables JSON. */
    VARIABLE,

    /** A literal argument of a root field; [BatchVariable.path] starts with the field's response key. */
    ARGUMENT,
}

data class BatchVariable(
    /** Path segments; list elements are `[index]` segments. */
    val path: List<String>,
    val type: String? = null,
    val kind: BatchVariableKind = BatchVariableKind.VARIABLE,
) {
    /** Unique key, also shown to the user: `$input.items[0].id` for variables, `user.id` for arguments. */
    val key: String
        get() {
            val joined = BatchVariableCollector.joinPath(path)
            return if (kind == BatchVariableKind.ARGUMENT) joined else "$$joined"
        }
}

/** A payload set: where the payloads come from and which JSON type they are sent as. */
data class PayloadSetConfig(
    val source: PayloadSource,
    val valueType: PayloadValueType = PayloadValueType.AUTO,
)

data class BatchAttackConfig(
    val mode: BatchMode,
    val attackType: IntruderAttackType,
    /** [BatchVariable.key]s of the selected variables. */
    val selectedVariables: List<String>,
    val sharedSource: PayloadSetConfig?,
    val perVariableSources: Map<String, PayloadSetConfig>,
    /** Maximum number of batched items per HTTP request; 0 sends everything in one request. */
    val batchSize: Int = 0,
) {
    val effectiveAttackType: IntruderAttackType get() = attackType.effectiveFor(selectedVariables.size)

    fun usesSharedPayload(): Boolean = effectiveAttackType.usesSharedPayloadSet
}
