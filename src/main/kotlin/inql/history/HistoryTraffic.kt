package inql.history

import burp.Burp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

internal object HistoryTraffic {
    data class Entry(
        val request: HttpRequest,
        val response: HttpResponse?,
    )

    fun entriesForHost(filterHostKey: String): List<Entry> {
        val results = LinkedHashMap<String, Entry>()

        fun addEntry(request: HttpRequest, response: HttpResponse?) {
            val requestKey = HistoryHostKey.fromRequest(request) ?: return
            if (!HistoryHostKey.matches(requestKey, filterHostKey)) return
            results.putIfAbsent(fingerprint(request), Entry(request, response))
        }

        for (item in Burp.Montoya.proxy().history()) {
            addEntry(item.finalRequest(), item.originalResponse())
        }

        for (item in Burp.Montoya.siteMap().requestResponses()) {
            addEntry(item.request(), item.response())
        }

        return results.values.toList()
    }

    fun fingerprint(request: HttpRequest): String {
        return "${request.method()}:${request.url()}:${request.bodyToString().hashCode()}"
    }
}
