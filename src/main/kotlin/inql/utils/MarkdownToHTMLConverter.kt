package inql.utils

import burp.Burp
import burp.api.montoya.http.HttpService
import com.vladsch.flexmark.parser.Parser
import com.vladsch.flexmark.html.HtmlRenderer
import burp.api.montoya.http.message.requests.HttpRequest
import java.net.URL

internal object MarkdownToHtmlConverter {
    fun downloadMarkdown(url: String): String {
        val parsedUrl = URL(url)
        var path = parsedUrl.path.ifEmpty { "/" }
        val host = parsedUrl.host
        if (parsedUrl.query?.isNotBlank() == true) path = "$path?${parsedUrl.query}"
        val request: HttpRequest = HttpRequest.httpRequest()
            .withService(HttpService.httpService(url))
            .withMethod("GET")
            .withAddedHeader("Host", host)
            .withPath(path)
            .withBody("")
            .withDefaultHeaders()

        val response = Burp.Montoya.http().sendRequest(request)
        val resp = response.response() ?: throw Exception("Failed to fetch $url")

        val status = resp.statusCode()
        if (status < 200 || status >= 300) throw Exception("Failed to fetch ${url}: $status")
        return resp.body().bytes.toString(Charsets.UTF_8) // not .bodyToString() because we want to keep emojis from HTML
    }

    fun renderMarkdownToHtml(text: String): String {
        val parser = Parser.builder().build()
        val document = parser.parse(text)
        val renderer = HtmlRenderer.builder().build()
        return renderer.render(document)
    }
}