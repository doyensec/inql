package inql.utils

import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

fun HttpRequest.withUpsertedHeader(name: String, value: String): HttpRequest {
    var updateOnly = false
    for (header in this.headers()) {
        if (header.name().lowercase() == name.lowercase()) {
            updateOnly = true
            break
        }
    }
    return if (updateOnly) {
        this.withUpdatedHeader(name, value)
    } else {
        this.withAddedHeader(name, value)
    }
}

fun HttpRequest.withUpsertedHeaders(newHeaders: Map<String, String>): HttpRequest {
    var out = this
    val keys = this.headers().map { it.name().lowercase() }.toSet()
    for ((k, v) in newHeaders) {
        out = if (keys.contains(k.lowercase())) {
            out.withUpdatedHeader(k, v)
        } else {
            out.withAddedHeader(k, v)
        }
    }
    return out
}

fun HttpResponse.withUpsertedHeader(name: String, value: String): HttpResponse {
    var updateOnly = false
    for (header in this.headers()) {
        if (header.name().lowercase() == name.lowercase()) {
            updateOnly = true
            break
        }
    }
    return if (updateOnly) {
        this.withUpdatedHeader(name, value)
    } else {
        this.withAddedHeader(name, value)
    }
}

fun HttpResponse.withUpsertedHeaders(newHeaders: Map<String, String>): HttpResponse {
    var out = this
    val keys = this.headers().map { it.name().lowercase() }.toSet()
    for ((k, v) in newHeaders) {
        out = if (keys.contains(k.lowercase())) {
            out.withUpdatedHeader(k, v)
        } else {
            out.withAddedHeader(k, v)
        }
    }
    return out
}

fun List<HttpHeader>.asMap(): Map<String, String> {
    return this.associate { e -> e.name() to e.value() }
}

fun List<HttpHeader>.get(name: String): String? {
    return this.find { it.name().equals(name, ignoreCase = true)}?.value()
}