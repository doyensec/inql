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
    val start: Int,
    val end: Int,
    val ts: LocalDateTime,
    val uuid: String,
) :
    SavesDataToProject {
    constructor(url: String, req: HttpRequest, resp: HttpResponse?, start: Int, end: Int) : this(
        url,
        req,
        resp,
        start,
        end,
        LocalDateTime.now(),
        "Attack.${UUID.randomUUID()}",
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
        attackObj.setInteger("start", this.start)
        attackObj.setInteger("end", this.end)
        attackObj.setString("ts", this.ts.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
        return attackObj
    }

    class Deserializer(key: String) : DeserializerFactory<Attack>(key) {
        override fun burpDeserialize(obj: PersistedObject) {
            this.deserialized = Attack(
                obj.getString("url"),
                obj.getHttpRequest("request"),
                obj.getHttpResponse("response"),
                obj.getInteger("start"),
                obj.getInteger("end"),
                LocalDateTime.parse(obj.getString("ts"), DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                obj.getString("id"),
            )
        }
    }
}
