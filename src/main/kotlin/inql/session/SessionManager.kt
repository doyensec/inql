package inql.session

import java.net.URI

object SessionManager {
    private val sessions = mutableMapOf<String, Session>()
    private val reservedIds = mutableSetOf<String>()

    /**
     * Find the next available session id based on the url.
     *
     * E.g. for `https://some.example.com/graphql` the first session id would be `some-example`, if that's not available
     * `some-example-2` would be tried, and so on.
     *
     * @param url the url to base the session id on
     * @return the next available session id
     */
    private fun generateNextSessionId(url: String): String {
        val baseId = calculateBaseId(url)
        var derivedId = baseId
        var counter = 2

        while (reservedIds.contains(derivedId) || sessions.containsKey(derivedId)) {
            derivedId = "$baseId-$counter"
            counter++
        }

        reservedIds.add(derivedId)
        return derivedId
    }

    /**
     * Generate a new session id based on the url.
     *
     * @param url the url to base the session id on
     * @param oldSessionId the old session id to remove from reservedIds
     * @return the new session id
     */
    fun newSessionId(url: String, oldSessionId: String? = null): String {
        if (oldSessionId != null) {
            reservedIds.remove(oldSessionId)
        }
        return generateNextSessionId(url)
    }

    private fun calculateBaseId(url: String): String {
        val uri = URI.create(url)
        val hostnameParts = uri.host.split(".")
        return if (hostnameParts.size >= 2) {
            hostnameParts.subList(0, hostnameParts.size - 1).joinToString("-")
        } else {
            uri.host
        }
    }

    fun getSession(id: String): Session? = sessions[id]

    fun addSession(session: Session) {
        sessions[session.sessionId] = session
        if (reservedIds.contains(session.sessionId)) {
            reservedIds.remove(session.sessionId)
        }
    }

    fun removeSession(id: String) {
        sessions.remove(id)
    }

    /**
     * Update the session id of an existing session. Will not overwrite an existing session.
     *
     * @oldId the old session id
     * @newId the new session id
     * @return true if the Session becomes available by the new id, false otherwise
     */
    fun updateSessionId(oldId: String, newId: String): Boolean {
        // check that sessionId is alphanumeric, with underscores / dashes / dots only
        if (!newId.matches(Regex("^[a-zA-Z0-9_.-]*$"))) {
            return false
        }

        if (oldId == newId) {
            // no op, but not an error
            return true
        }

        // check that the new sessionId is available
        if (sessions.containsKey(newId)) {
            return false
        }

        // check that the old sessionId exists
        val session = sessions.remove(oldId) ?: return false

        // TODO: figure out a way to do this atomically / transactionally
        // right now the correctness is dependent on these operations being non-async, but there's no error handling
        // plus a short window is present between operations when the session is not available by any id

        // Remove the old session from the project file and sessions map
        session.deleteFromProjectFile(false)
        this.removeSession(oldId)

        // Update the session id and save it to the project file & sessions map
        session.sessionId = newId
        this.addSession(session)
        session.saveToProjectFile()

        return true
    }
}
