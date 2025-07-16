package inql.utils

import org.intellij.markdown.MarkdownElementTypes
import org.intellij.markdown.flavours.commonmark.CommonMarkFlavourDescriptor
import org.intellij.markdown.ast.ASTNode
import com.vladsch.flexmark.parser.Parser
import com.vladsch.flexmark.html.HtmlRenderer
import org.intellij.markdown.parser.MarkdownParser
import okhttp3.OkHttpClient
import okhttp3.Request

internal object MarkdownToHtmlConverter {
    fun downloadMarkdown(url: String): String {
        val client = OkHttpClient()
        val request = Request.Builder().url(url).build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw Exception("Failed to fetch ${url}: ${response.code}")
            return response.body?.string() ?: throw Exception("Empty response body")
        }
    }

    fun renderMarkdownToHtml(text: String): String {
        val parser = Parser.builder().build()
        val document = parser.parse(text)
        val renderer = HtmlRenderer.builder().build()
        return renderer.render(document)
    }
}