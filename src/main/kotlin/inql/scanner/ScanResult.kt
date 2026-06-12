package inql.scanner

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import graphql.schema.GraphQLSchema
import inql.graphql.GQLSchema
import inql.savestate.DeserializerFactory
import inql.savestate.SavesDataToProject
import inql.schema.corrections.SchemaCorrections
import inql.schema.corrections.SchemaCorrectionsService
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*

class ScanResult private constructor(
    val host: String,
    val requestTemplate: HttpRequest,
    val parsedSchema: GQLSchema,
    val jsonSchema: String? = null,
    val sdlSchema: String? = null,
    val schemaDiscoverySource: SchemaDiscoverySource = SchemaDiscoverySource.INTROSPECTION,
    val schemaCorrections: SchemaCorrections = SchemaCorrections.EMPTY,
    val ts: LocalDateTime,
    val uuid: String,
) : SavesDataToProject {
    constructor(
        host: String,
        requestTemplate: HttpRequest,
        parsedSchema: GQLSchema,
        jsonSchema: String? = null,
        sdlSchema: String? = null,
        schemaDiscoverySource: SchemaDiscoverySource = SchemaDiscoverySource.INTROSPECTION,
        schemaCorrections: SchemaCorrections = SchemaCorrections.EMPTY,
    ) : this(
        host,
        requestTemplate,
        parsedSchema,
        jsonSchema,
        sdlSchema,
        schemaDiscoverySource,
        schemaCorrections,
        LocalDateTime.now(),
        UUID.randomUUID().toString(),
    )

    class Deserializer(key: String) : DeserializerFactory<ScanResult>(key) {
        override fun burpDeserialize(obj: PersistedObject) {
            val jsonSchema = obj.getString("jsonSchema")
            val sdlSchema = obj.getString("sdlSchema")
            val schemaPayload = jsonSchema ?: sdlSchema
            if (schemaPayload == null) {
                throw IllegalStateException(
                    "Persisted ScanResult is missing schema payload (uuid=${obj.getString("uuid")})",
                )
            }
            val schema = GQLSchema(schemaPayload)
            val sourceStr = obj.getString("schemaDiscoverySource")
            val schemaDiscoverySource = sourceStr?.let { s ->
                runCatching { SchemaDiscoverySource.valueOf(s) }.getOrNull()
            } ?: SchemaDiscoverySource.INTROSPECTION
            val corrections = SchemaCorrections.fromJson(obj.getString("schemaCorrections"))
            this.deserialized = ScanResult(
                obj.getString("host"),
                obj.getHttpRequest("template"),
                schema,
                jsonSchema,
                sdlSchema,
                schemaDiscoverySource,
                corrections,
                LocalDateTime.parse(obj.getString("ts"), DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                obj.getString("uuid"),
            )
        }
    }

    override val saveStateKey: String
        get() = "Scanner.ScanResult.${this.uuid}"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject>? = null

    fun withUpdatedRequestTemplate(newTemplate: HttpRequest): ScanResult {
        return ScanResult(
            host,
            newTemplate,
            parsedSchema,
            jsonSchema,
            sdlSchema,
            schemaDiscoverySource,
            schemaCorrections,
            ts,
            uuid,
        )
    }

    fun withUpdatedSchema(
        newSchema: GQLSchema,
        jsonSchema: String? = newSchema.jsonSchema,
        sdlSchema: String? = newSchema.sdlSchema,
    ): ScanResult {
        return ScanResult(
            host,
            requestTemplate,
            newSchema,
            jsonSchema,
            sdlSchema,
            schemaDiscoverySource,
            schemaCorrections,
            ts,
            uuid,
        )
    }

    fun withCorrections(corrections: SchemaCorrections, newSchema: GQLSchema? = null): ScanResult {
        val schema = newSchema ?: parsedSchema
        return ScanResult(
            host,
            requestTemplate,
            schema,
            schema.jsonSchema,
            schema.sdlSchema,
            schemaDiscoverySource,
            corrections,
            ts,
            uuid,
        )
    }

    fun withCorrectionsOnly(corrections: SchemaCorrections): ScanResult {
        return ScanResult(
            host,
            requestTemplate,
            parsedSchema,
            jsonSchema,
            sdlSchema,
            schemaDiscoverySource,
            corrections,
            ts,
            uuid,
        )
    }

    @Transient
    private var cachedEffectiveSchema: GQLSchema? = null

    @Transient
    private var cachedEffectiveCorrections: SchemaCorrections? = null

    fun effectiveParsedSchema(): GQLSchema {
        if (cachedEffectiveSchema != null && cachedEffectiveCorrections == schemaCorrections) {
            return cachedEffectiveSchema!!
        }
        val effective = SchemaCorrectionsService.applyToGqlSchema(parsedSchema, schemaCorrections)
        cachedEffectiveSchema = effective
        cachedEffectiveCorrections = schemaCorrections
        return effective
    }

    fun effectiveGraphQLSchema(): GraphQLSchema = effectiveParsedSchema().schema

    fun hasManualCorrections(): Boolean = schemaCorrections.hasActiveCorrections()

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setString("uuid", this.uuid)
        obj.setString("ts", ts.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
        obj.setString("host", host)
        obj.setHttpRequest("template", requestTemplate)
        obj.setString("sdlSchema", sdlSchema ?: parsedSchema.sdlSchema)
        if (jsonSchema != null) {
            obj.setString("jsonSchema", jsonSchema)
        }
        obj.setString("schemaDiscoverySource", schemaDiscoverySource.name)
        if (schemaCorrections.hasActiveCorrections()) {
            obj.setString("schemaCorrections", schemaCorrections.toJson())
        }
        return obj
    }
}
