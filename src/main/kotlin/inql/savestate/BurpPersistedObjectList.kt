package inql.savestate

import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.persistence.PersistedObject

fun PersistedObject.getChildObjectList(key: String): List<PersistedObject>? {
    val listKey = "objlst_${key}_${key.hashCode()}"
    val internalObj = this.getChildObject(listKey) ?: return null
    val size = internalObj.getInteger("size") ?: return null
    val lst = ArrayList<PersistedObject>(size)
    for (idx in 0..<size) {
        val obj = internalObj.getChildObject(idx.toString())
        lst.add(obj)
    }
    return lst
}

fun PersistedObject.setChildObjectList(key: String, value: List<PersistedObject>) {
    val internalObj = PersistedObject.persistedObject()
    internalObj.setString("key", key)
    internalObj.setInteger("size", value.size)
    for (idx in value.indices) {
        internalObj.setChildObject(idx.toString(), value[idx])
    }

    // A deterministic key that should avoid conflicts with other possible objects
    val listKey = "objlst_${key}_${key.hashCode()}"
    this.setChildObject(listKey, internalObj)
}

fun PersistedObject.deleteChildObjectList(key: String) {
    val listKey = "objlst_${key}_${key.hashCode()}"
    this.deleteChildObject(listKey)
}

fun PersistedObject.childObjectListKeys(): Set<String> {
    return this.childObjectKeys().filter { it.startsWith("objlst_") }.toSet()
}

fun getSaveStateKeys(c: Collection<SavesDataToProject>): PersistedList<String> {
    val lst = PersistedList.persistedStringList()
    lst.addAll(c.map { it.saveStateKey })
    return lst
}