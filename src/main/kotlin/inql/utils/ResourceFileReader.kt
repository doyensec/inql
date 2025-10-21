package inql.utils

class ResourceFileReader {
    companion object {
        fun readFile(fileName: String): String {
            return this::class.java.classLoader
                    .getResource(fileName)
                    ?.readText()
                    ?: throw IllegalArgumentException("File $fileName not found in resources!")
        }
    }
}