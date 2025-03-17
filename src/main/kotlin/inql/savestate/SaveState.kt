package inql.savestate

import burp.Burp
import burp.api.montoya.persistence.PersistedObject
import inql.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

interface LoadsDataFromProject : BurpDeserializable {
    companion object {
        val coroutineScope = CoroutineScope(Dispatchers.IO)
    }

    val saveStateKey: String

    fun dataPresentInProjectFile(): Boolean {
        val key = this.saveStateKey
        val obj = Burp.Montoya.persistence().extensionData().getChildObject("inql_savestate.$key")
        return obj != null
    }

    fun loadFromProjectFile(): Boolean {
        val key = this.saveStateKey
        Logger.debug("[$key] Trying to load data from project file")
        val obj = Burp.Montoya.persistence().extensionData().getChildObject("inql_savestate.$key")
        if (obj == null) {
            Logger.warning("[$key] No savestate with this key found in this project file")
            return false
        }
        try {
            Logger.debug("[$key] Found, deserializing...")
            this.burpDeserialize(obj)
        } catch (e: Exception) {
            Logger.error("[$key] Failed deserializing object's data")
            Logger.error(e.stackTraceToString())
            return false
        }
        Logger.info("[$key] Load from project completed")
        return true
    }

    fun loadFromProjectFileAsync() {
        coroutineScope.launch {
            this@LoadsDataFromProject.loadFromProjectFile()
        }
    }
}

interface SavesDataToProject : BurpSerializable {
    companion object {
        val coroutineScope = CoroutineScope(Dispatchers.IO)
    }

    val saveStateKey: String
    fun saveToProjectFile(processChildren: Boolean = true): String? {
        val key = this.saveStateKey
        val obj: PersistedObject
        Logger.debug("[$key] Saving data to project file (with children: $processChildren)")
        try {
            // Processing children in a separate step allows to do partial updates
            // where for example a children is updated/created/deleted and saved independently of its parent.
            // Then we can invoke saveToProjectFile(false) to update the parent's children list but not
            // all the underlying children, saving some IO time
            if (processChildren) {
                Logger.debug("[$key] Processing children first...")
                this.saveChildrenObjectsToProjectFile()
            }
            Logger.debug("[$key] Serializing data")
            obj = this.burpSerialize()
        } catch (e: Exception) {
            Logger.error("[$key] Failed serializing the object's data")
            Logger.error(e.stackTraceToString())
            return null
        }
        Logger.info("[$key] Serialization completed successfully")
        Burp.Montoya.persistence().extensionData().setChildObject("inql_savestate.$key", obj)
        return key
    }

    fun saveToProjectFileAsync(processChildren: Boolean = true) {
        coroutineScope.launch {
            this@SavesDataToProject.saveToProjectFile(processChildren)
        }
    }

    fun saveChildrenObjectsToProjectFile() {
        val children = this.getChildrenObjectsToSave() ?: return
        for (child in children) {
            child.saveToProjectFile()
        }
    }

    fun getChildrenObjectsToSave(): Collection<SavesDataToProject>?

    fun updateChildObject(obj: SavesDataToProject) {
        Logger.info("[${this.saveStateKey}] Updating child object: ${obj.saveStateKey}")
        obj.saveToProjectFile()
        this.saveToProjectFile(false)
    }

    fun updateChildObjectAsync(obj: SavesDataToProject) {
        coroutineScope.launch {
            this@SavesDataToProject.updateChildObject(obj)
        }
    }

    fun deleteFromProjectFile(deleteChildren: Boolean = true) {
        val key = this.saveStateKey
        Burp.Montoya.persistence().extensionData().deleteChildObject("inql_savestate.$key")
        if (deleteChildren) {
            val children = this.getChildrenObjectsToSave() ?: return
            for (child in children) {
                child.deleteFromProjectFile(true)
            }
        }
    }

    fun deleteFromProjectFileAsync(deleteChildren: Boolean = true) {
        coroutineScope.launch {
            this@SavesDataToProject.deleteFromProjectFile(deleteChildren)
        }
    }

    fun deleteChildObject(obj: SavesDataToProject) {
        obj.deleteFromProjectFile()
        this.saveToProjectFile(false)
    }

    fun deleteChildObjectAsync(obj: SavesDataToProject) {
        coroutineScope.launch {
            this@SavesDataToProject.deleteChildObject(obj)
        }
    }
}

interface SavesAndLoadData : SavesDataToProject, LoadsDataFromProject

// This Factory-Deserializer class allows to create a Kotlin object from the deserialization
// of data from the project file, instead of creating the object first and then loading data into it
abstract class DeserializerFactory<T>(val key: String) : LoadsDataFromProject {
    protected var deserialized: T? = null
    fun get(): T? {
        this.loadFromProjectFile()
        return deserialized
    }

    override val saveStateKey: String
        get() = this.key
}
