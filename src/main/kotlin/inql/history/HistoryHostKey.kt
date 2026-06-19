package inql.history

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import java.net.URI
import java.net.URISyntaxException

object HistoryHostKey {
    fun fromHttpService(service: HttpService): String {
        val host = service.host().lowercase()
        val port = service.port()
        val isDefaultPort = (service.secure() && port == 443) || (!service.secure() && port == 80)
        return if (isDefaultPort) host else "$host:$port"
    }

    fun fromRequest(request: HttpRequest): String? {
        try {
            request.httpService()?.let { return fromHttpService(it) }
        } catch (_: Exception) {
            // Malformed or incomplete requests may not expose a service.
        }
        return try {
            fromUrl(request.url())
        } catch (_: Exception) {
            null
        }
    }

    fun fromUrl(url: String): String? {
        return try {
            val uri = URI.create(url)
            val host = uri.host?.lowercase() ?: return null
            val port = uri.port
            val isDefaultPort = port == -1 ||
                (uri.scheme.equals("https", ignoreCase = true) && port == 443) ||
                (uri.scheme.equals("http", ignoreCase = true) && port == 80)
            if (isDefaultPort) host else "$host:$port"
        } catch (_: URISyntaxException) {
            null
        }
    }

    fun normalize(key: String): String = key.lowercase()

    /**
     * A host-only filter (e.g. "localhost") matches any port on that host.
     * A host:port filter matches the exact service or a host-only key for the same hostname.
     */
    fun matches(requestKey: String, filterKey: String): Boolean {
        val request = normalize(requestKey)
        val filter = normalize(filterKey)
        if (request == filter) return true
        if (!filter.contains(':') && (request == filter || request.startsWith("$filter:"))) return true
        if (!request.contains(':') && filter.startsWith("$request:")) return true
        return false
    }
}
