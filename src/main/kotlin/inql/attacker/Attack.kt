package inql.attacker

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.persistence.PersistedObject
import inql.savestate.DeserializerFactory
import inql.savestate.SavesDataToProject
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*

class Attack private constructor(
    val url: String,
    val req: HttpRequest,
    var resp: HttpResponse?,
    val ts: LocalDateTime,
    val uuid: String,
    val mode: BatchMode,
    val itemCount: Int,
    val part: Int,
    val partCount: Int,
    var error: String?,
    var responseTimeMs: Long?,
) :
    SavesDataToProject {
    /** Results of the attack this request belongs to. Session only, not saved to the project. */
    var run: BatchRun? = null

    constructor(
        url: String,
        req: HttpRequest,
        resp: HttpResponse?,
        mode: BatchMode,
        itemCount: Int,
        part: Int = 1,
        partCount: Int = 1,
    ) : this(
        url,
        req,
        resp,
        LocalDateTime.now(),
        "Attack.${UUID.randomUUID()}",
        mode,
        itemCount,
        part,
        partCount,
        null,
        null,
    )

    override val saveStateKey: String
        get() = this.uuid

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject>? = null

    override fun burpSerialize(): PersistedObject {
        val attackObj = PersistedObject.persistedObject()
        attackObj.setString("id", this.uuid)
        attackObj.setString("url", this.url)
        attackObj.setHttpRequest("request", this.req)
        if (this.resp != null) {
            attackObj.setHttpResponse("response", this.resp)
        }
        attackObj.setString("mode", this.mode.name)
        attackObj.setInteger("itemCount", this.itemCount)
        attackObj.setInteger("part", this.part)
        attackObj.setInteger("partCount", this.partCount)
        this.error?.let { attackObj.setString("error", it) }
        this.responseTimeMs?.let { attackObj.setLong("responseTimeMs", it) }
        attackObj.setString("ts", this.ts.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
        return attackObj
    }

    class Deserializer(key: String) : DeserializerFactory<Attack>(key) {
        override fun burpDeserialize(obj: PersistedObject) {
            // Attacks saved before batching was reworked only have the "start" and "end" of their item range.
            val itemCount = obj.getInteger("itemCount")?.takeIf { it > 0 }
                ?: ((obj.getInteger("end") ?: 0) - (obj.getInteger("start") ?: 0)).coerceAtLeast(0)
            this.deserialized = Attack(
                obj.getString("url"),
                obj.getHttpRequest("request"),
                obj.getHttpResponse("response"),
                LocalDateTime.parse(obj.getString("ts"), DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                obj.getString("id"),
                BatchMode.fromStored(obj.getString("mode")),
                itemCount,
                obj.getInteger("part")?.takeIf { it > 0 } ?: 1,
                obj.getInteger("partCount")?.takeIf { it > 0 } ?: 1,
                obj.getString("error"),
                obj.getLong("responseTimeMs"),
            )
        }
    }
}
