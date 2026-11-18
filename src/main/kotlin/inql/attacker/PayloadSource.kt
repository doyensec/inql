package inql.attacker

import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonPrimitive
import inql.Logger
import java.io.File
import java.util.concurrent.ConcurrentHashMap

sealed class PayloadSource {
    data class FilePath(val path: String) : PayloadSource()
    data class NumberRange(val from: Int, val to: Int, val minDigits: Int = 0) : PayloadSource()
    data class BruteForce(val charset: String, val minLen: Int, val maxLen: Int) : PayloadSource()
    data class WordList(val words: List<String>) : PayloadSource()
    data class NullPayloads(val count: Int) : PayloadSource()

    companion object {
        const val MAX_LINE_CHARS = 8192
        const val MAX_GENERATED = 100_000

        /** Line counts of payload files, valid while the file's size and modification time are unchanged. */
        private val fileLineCounts = ConcurrentHashMap<String, Triple<Long, Long, Long>>()

        /** The payloads of a simple list: lines that are not empty after trailing whitespace is removed. */
        fun words(lines: List<String>): List<String> = lines.map { it.trimEnd() }.filter { it.isNotEmpty() }

        fun count(source: PayloadSource): Long {
            return when (source) {
                is FilePath -> countFileLines(source.path)
                is NumberRange -> {
                    if (source.from > source.to) 0L
                    else source.to.toLong() - source.from.toLong() + 1L
                }
                is BruteForce -> bruteForceCount(source.charset.length, source.minLen, source.maxLen)
                is WordList -> words(source.words).size.toLong()
                is NullPayloads -> source.count.toLong().coerceAtLeast(0)
            }
        }

        fun countOrZero(source: PayloadSource?): Long {
            if (source == null) return 0
            return try {
                count(source)
            } catch (_: Exception) {
                0
            }
        }

        fun load(source: PayloadSource): List<JsonElement> {
            return when (source) {
                is FilePath -> loadFile(source.path)
                is NumberRange -> loadNumberRange(source.from, source.to, source.minDigits)
                is BruteForce -> loadBruteForce(source.charset, source.minLen, source.maxLen)
                is WordList -> loadWordList(source.words)
                is NullPayloads -> loadNullPayloads(source.count)
            }
        }

        /** Counted on the UI thread whenever the payload settings change, so the result is cached per file. */
        private fun countFileLines(path: String): Long {
            val file = File(path)
            if (!file.isFile) return 0
            val modified = file.lastModified()
            val length = file.length()
            fileLineCounts[path]?.let { (cachedModified, cachedLength, count) ->
                if (cachedModified == modified && cachedLength == length) return count
            }
            var count = 0L
            file.bufferedReader().use { reader ->
                reader.lineSequence().forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isNotEmpty() && trimmed.length <= MAX_LINE_CHARS) {
                        count++
                    }
                }
            }
            fileLineCounts[path] = Triple(modified, length, count)
            return count
        }

        private fun bruteForceCount(charsetLen: Int, minLen: Int, maxLen: Int): Long {
            if (charsetLen <= 0 || minLen < 0 || maxLen < minLen) return 0
            var total = 0L
            if (minLen == 0) total++
            var pow = 1L
            for (len in 1..maxLen) {
                if (pow > Long.MAX_VALUE / charsetLen) return Long.MAX_VALUE
                pow *= charsetLen
                if (len >= minLen) {
                    if (total > Long.MAX_VALUE - pow) return Long.MAX_VALUE
                    total += pow
                }
            }
            return total
        }

        private fun loadFile(path: String): List<JsonElement> {
            val file = File(path)
            if (!file.isFile) {
                throw PayloadSourceException("Payload file not found: $path")
            }

            val values = ArrayList<JsonElement>()
            var skippedLong = 0
            file.bufferedReader().use { reader ->
                reader.lineSequence().forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty()) return@forEach
                    if (trimmed.length > MAX_LINE_CHARS) {
                        skippedLong++
                        return@forEach
                    }
                    values.add(JsonPrimitive(trimmed))
                }
            }
            if (skippedLong > 0) {
                Logger.warning(
                    "Skipped $skippedLong wordlist lines longer than $MAX_LINE_CHARS characters from $path",
                )
            }
            return values
        }

        private fun loadNumberRange(from: Int, to: Int, minDigits: Int): List<JsonElement> {
            if (from > to) {
                throw PayloadSourceException("Number range From ($from) is greater than To ($to).")
            }
            val total = to.toLong() - from.toLong() + 1
            if (total > MAX_GENERATED) {
                throw PayloadSourceException(
                    "Number range produces $total values, which is too large. Use a smaller range or a file.",
                )
            }
            val values = ArrayList<JsonElement>(total.toInt())
            var n = from.toLong()
            repeat(total.toInt()) {
                values.add(if (minDigits > 0) JsonPrimitive(padNumber(n, minDigits)) else JsonPrimitive(n))
                n++
            }
            return values
        }

        private fun padNumber(n: Long, minDigits: Int): String {
            val digits = kotlin.math.abs(n).toString().padStart(minDigits, '0')
            return if (n < 0) "-$digits" else digits
        }

        private fun loadBruteForce(charset: String, minLen: Int, maxLen: Int): List<JsonElement> {
            val charsetChars = charset.toCharArray()
            if (charsetChars.isEmpty()) {
                throw PayloadSourceException("Brute force character set is empty.")
            }
            if (minLen < 0) {
                throw PayloadSourceException("Brute force minimum length cannot be negative.")
            }
            if (maxLen < minLen) {
                throw PayloadSourceException("Brute force maximum length is smaller than the minimum.")
            }

            val values = ArrayList<JsonElement>()
            if (minLen == 0) {
                values.add(JsonPrimitive(""))
            }
            val start = maxOf(minLen, 1)
            val prefix = StringBuilder()
            for (len in start..maxLen) {
                generateBrute(charsetChars, prefix, len, values)
            }
            return values
        }

        private fun generateBrute(
            charset: CharArray,
            prefix: StringBuilder,
            len: Int,
            values: MutableList<JsonElement>,
        ) {
            if (prefix.length == len) {
                if (values.size >= MAX_GENERATED) {
                    throw PayloadSourceException(
                        "Brute force would produce more than $MAX_GENERATED payloads. Reduce length or character set.",
                    )
                }
                values.add(JsonPrimitive(prefix.toString()))
                return
            }
            for (c in charset) {
                prefix.append(c)
                generateBrute(charset, prefix, len, values)
                prefix.deleteCharAt(prefix.length - 1)
            }
        }

        private fun loadWordList(words: List<String>): List<JsonElement> {
            val values = words(words).map { JsonPrimitive(it) }
            if (values.isEmpty()) {
                throw PayloadSourceException("Custom list is empty. Add at least one word.")
            }
            return values
        }

        private fun loadNullPayloads(count: Int): List<JsonElement> {
            if (count < 1) {
                throw PayloadSourceException("Null payload count must be at least 1.")
            }
            if (count > MAX_GENERATED) {
                throw PayloadSourceException("Null payload count is too large.")
            }
            return List(count) { JsonNull.INSTANCE }
        }
    }
}

class PayloadSourceException(message: String) : Exception(message)
