import burp.Burp
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import inql.Logger
import org.apache.commons.validator.routines.UrlValidator
import java.net.URI

fun isValidUrl(urlString: String): Boolean {
    val urlValidator = UrlValidator(arrayOf("http", "https"))
    return urlValidator.isValid(urlString)
}

private val USELESS_HEADERS = setOf(
    "host",
    "connection",
    "content-length"
)

/**
 * Fetches the headers of the last request made to the specified host.
 *
 * @param host The host to fetch the headers for.
 * @param pathFilter The path to filter the requests by.
 * @param headersFilter The headers to filter the requests by (OR matching).
 */
fun fetchHeadersForHost(
    host: String,
    pathFilter: String? = null,
    headersFilter: List<Pair<String, String>>? = null,
): List<HttpHeader>? {
    val lowercaseHeaders: Map<String, Set<String>>? = headersFilter
        ?.groupBy({ it.first.lowercase() }, { it.second.lowercase() })
        ?.mapValues { it.value.toSet() }

    val requests: List<ProxyHttpRequestResponse> = Burp.Montoya.proxy().history { requestResponse ->
        val request = requestResponse.finalRequest()

        // The URL returned by request.url() is sometimes URL-decoded, meaning URI.create() might throw
        // an exception. The correct way to handle this is to URL-encode the URL before creating the URI,
        // but we're taking a shortcut here for performance reasons - review this if there are issues.
        val url: URI? = try {
            URI.create(request.url())
        } catch (e: IllegalArgumentException) {
            null
        }

        if (url == null) {
            Logger.info("Safely skipping request with invalid URL")
            return@history false
        }

        // Check that the host matches exactly
        if (url.host.lowercase() != host.lowercase()) {
            return@history false
        }

        // Check that the path matches the filter ('starts with' to support /graphql/OperationName pattern)
        if (!pathFilter.isNullOrEmpty() && !url.path.startsWith(pathFilter)) {
            return@history false
        }

        // Check that the headers match the filter (OR matching)
        return@history lowercaseHeaders?.let { filter ->
            request.headers().any { header ->
                val name = header.name().lowercase()
                filter[name]?.contains(header.value().lowercase()) ?: false
            }
        } ?: false
    }

    if (requests.isEmpty()) {
        Logger.warning("No request found during headers fetching")
        return null
    } else {
        Logger.info("Found ${requests.size} matching requests during headers fetching")
        return requests.last().finalRequest().headers().filter { header ->
            header.name().lowercase() !in USELESS_HEADERS
        }
    }
}
