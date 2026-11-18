package inql.bruteforcer

internal sealed interface Step {
    data class Field(val parent: String, val name: String) : Step
    data class Fragment(val type: String) : Step
}

internal fun chainKey(operation: String, fieldNames: List<String>) = (listOf(operation) + fieldNames).joinToString("/")

internal class Path(val operation: String, val steps: List<Step>) {
    val depth get() = steps.count { it is Step.Field }

    val fieldNames get() = steps.filterIsInstance<Step.Field>().map { it.name }

    val key get() = chainKey(operation, fieldNames)

    fun keyWith(field: String) = chainKey(operation, fieldNames + field)

    fun field(parent: String, name: String) = Path(operation, steps + Step.Field(parent, name))
    fun fragment(type: String) = Path(operation, steps + Step.Fragment(type))
}
