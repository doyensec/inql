package inql.utils

class JsonFileReader {
    companion object {
        fun readJsonFile(fileName: String): String {
            return this::class.java.classLoader
                    .getResource(fileName)
                    ?.readText()
                    ?: throw IllegalArgumentException("File $fileName not found in resources!")
        }
    }
}