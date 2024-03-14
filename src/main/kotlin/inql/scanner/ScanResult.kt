package inql.scanner

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import inql.graphql.GQLSchemaMemoryBackedImpl
import inql.savestate.DeserializerFactory
import inql.savestate.SavesDataToProject
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*

class ScanResult private constructor(
    val host: String,
    val requestTemplate: HttpRequest,
    val parsedSchema: GQLSchemaMemoryBackedImpl,
    val jsonSchema: String? = null,
    val sdlSchema: String? = null,
    val ts: LocalDateTime,
    val uuid: String,
) : SavesDataToProject {
    constructor(
        host: String,
        requestTemplate: HttpRequest,
        parsedSchema: GQLSchemaMemoryBackedImpl,
        jsonSchema: String? = null,
        sdlSchema: String? = null,
    ) : this(host, requestTemplate, parsedSchema, jsonSchema, sdlSchema, LocalDateTime.now(), UUID.randomUUID().toString())

    class Deserializer(key: String) : DeserializerFactory<ScanResult>(key) {
        override fun burpDeserialize(obj: PersistedObject) {
            this.deserialized = ScanResult(
                obj.getString("host"),
                obj.getHttpRequest("template"),
                GQLSchemaMemoryBackedImpl.burpDeserialize(obj.getChildObject("schema")),
                obj.getString("jsonSchema"),
                obj.getString("sdlSchema"),
                LocalDateTime.parse(obj.getString("ts"), DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                obj.getString("uuid"),
            )
        }
    }

    override val saveStateKey: String
        get() = "Scanner.ScanResult.${this.uuid}"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject>? = null

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setString("uuid", this.uuid)
        obj.setString("ts", ts.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
        obj.setString("host", host)
        obj.setHttpRequest("template", requestTemplate)
        obj.setChildObject("schema", parsedSchema.burpSerialize())
        if (jsonSchema != null) obj.setString("jsonSchema", jsonSchema)
        if (sdlSchema != null) obj.setString("sdlSchema", sdlSchema)
        return obj
    }
}
