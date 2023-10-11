package inql

import burp.api.montoya.persistence.PersistedObject
import inql.savestate.DeserializerFactory
import inql.savestate.SavesDataToProject
import inql.savestate.getChildObjectList
import inql.savestate.setChildObjectList

class Profile(val name: String, val id: String, val host: String) : SavesDataToProject {
    class Deserializer(key: String) : DeserializerFactory<Profile>(key) {
        override fun burpDeserialize(obj: PersistedObject) {
            val p = Profile(obj.getString("name"), obj.getString("id"), obj.getString("host"))
            val headersLst = obj.getChildObjectList("headers")
            if (headersLst != null) {
                for (headerObj in headersLst) {
                    p.customHeaders[headerObj.getString("k")] = headerObj.getString("v")
                }
            }
            this.deserialized = p
        }
    }

    val customHeaders: MutableMap<String, String> = LinkedHashMap<String, String>()
    val cachedSchemas: MutableMap<String, String> = LinkedHashMap<String, String>()

    fun overwrite(headers: Map<String, String>) {
        this.customHeaders.clear()
        this.customHeaders.putAll(headers)
        this.saveToProjectFileAsync()
    }

    override val saveStateKey: String
        get() = "Profile.$id"

    override fun getChildrenObjectsToSave(): Collection<SavesDataToProject>? = null

    override fun burpSerialize(): PersistedObject {
        val obj = PersistedObject.persistedObject()
        obj.setString("name", name)
        obj.setString("id", id)
        obj.setString("host", host)
        val headersLst = ArrayList<PersistedObject>(this.customHeaders.size)
        for ((k, v) in this.customHeaders) {
            val headerObj = PersistedObject.persistedObject()
            headerObj.setString("k", k)
            headerObj.setString("v", v)
            headersLst.add(headerObj)
        }
        obj.setChildObjectList("headers", headersLst)
        return obj
    }

    override fun toString(): String {
        return name
    }

    fun upsertSchema(endpoint: String, schema: String) {
        this.cachedSchemas[endpoint] = schema
        this.saveToProjectFileAsync()
    }
}
