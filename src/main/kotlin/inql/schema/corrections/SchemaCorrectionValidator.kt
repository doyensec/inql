package inql.schema.corrections

import graphql.schema.GraphQLSchema
import graphql.schema.idl.SchemaGenerator
import graphql.schema.idl.SchemaParser
import graphql.schema.idl.errors.SchemaProblem
import inql.graphql.SchemaInspectionRuntimeWiring

object SchemaCorrectionValidator {
    data class ValidationResult(
        val valid: Boolean,
        val schema: GraphQLSchema? = null,
        val errors: List<String> = emptyList(),
    )

    fun validateSdl(sdl: String): ValidationResult {
        return try {
            val registry = SchemaParser().parse(sdl)
            val schema = SchemaGenerator().makeExecutableSchema(
                registry,
                SchemaInspectionRuntimeWiring.build(registry),
            )
            ValidationResult(valid = true, schema = schema)
        } catch (e: SchemaProblem) {
            ValidationResult(
                valid = false,
                errors = e.errors.map { it.message ?: it.toString() },
            )
        } catch (e: Exception) {
            ValidationResult(valid = false, errors = listOf(e.message ?: e.toString()))
        }
    }
}
