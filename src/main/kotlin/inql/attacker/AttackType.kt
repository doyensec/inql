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

/** Kinds of batch positions, in the order they are listed in the UI. */
enum class BatchVariableKind(val noun: String, val groupTitle: String) {
    /** A literal argument of a root field; [BatchVariable.path] starts with the field's response key. */
    ARGUMENT("argument", "Arguments"),

    /** A GraphQL variable, or a value nested in one; [BatchVariable.path] is its path in the variables JSON. */
    VARIABLE("variable", "Variables"),
}

data class BatchVariable(
    /** Path segments; list elements are `[index]` segments. */
    val path: List<String>,
    val type: String? = null,
    val kind: BatchVariableKind = BatchVariableKind.VARIABLE,
) {
    /**
     * Unique key identifying the position: `$input.items[0].id` for variables, `user.id` for arguments. The prefix
     * keeps an argument and a variable with the same path apart; show [name] or [displayName] to the user instead.
     */
    val key: String
        get() = if (kind == BatchVariableKind.ARGUMENT) name else "$$name"

    /** The position's path, e.g. `input.items[0].id`; shown where the kind is already clear, such as under a group heading. */
    val name: String
        get() = BatchVariableCollector.joinPath(path)

    /** The path with its kind, e.g. `input.items[0].id (variable)`; shown where variables and arguments mix. */
    val displayName: String
        get() = "$name (${kind.noun})"
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
