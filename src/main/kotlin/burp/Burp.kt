package burp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.Theme
import inql.Logger
import java.io.File
import java.io.InputStream
import java.util.zip.ZipFile

class Burp private constructor() {
    companion object {
        private lateinit var montoya: MontoyaApi
        val Montoya: MontoyaApi get() = montoya
        fun initialize(montoya: MontoyaApi) {
            if (this::montoya.isInitialized) throw Exception("Burp Global already initialized!")
            Burp.montoya = montoya
            System.setOut(montoya.logging().output())
            System.setErr(montoya.logging().error())
        }

        public fun isDarkMode(): Boolean = Burp.Montoya.userInterface().currentTheme() == Theme.DARK
        public fun findBurpJarPath(): String? {
            try {
                val classPath = System.getProperty("java.class.path", ".")
                val classPathElements =
                    classPath.split(System.getProperty("path.separator").toRegex()).dropLastWhile { it.isEmpty() }

                var burpJar: String? = null
                for (elem in classPathElements) {
                    try {
                        val zf = ZipFile(elem)

                        if (zf.getEntry("burp/StartBurp.class") != null) {
                            burpJar = elem
                            break
                        }
                        zf.close()
                    } catch (e: Exception) {
                        continue
                    }
                }

                return burpJar
            } catch (e: Exception) {
                Logger.warning("Cannot find burp jar file")
                Logger.warning(e.toString())
            }
            return null
        }

        public fun openBurpJar(): ZipFile? {
            val path: String = findBurpJarPath() ?: return null
            return ZipFile(path)
        }

        // https://stackoverflow.com/a/3923182
        public fun getResourceFromJar(burpJar: ZipFile?, path: String): InputStream? {
            if (burpJar == null) return null

            try {
                val entry = burpJar.getEntry(path)
                if (entry == null) {
                    Logger.warning("Resource not found in Burp Jar: $path")
                    return null
                }
                return burpJar.getInputStream(entry)
            } catch (e: Exception) {
                Logger.warning("Cannot load resource: $path")
                Logger.warning(e.toString())
                return null
            }
        }

        public fun getResourceFromBurpJar(path: String): InputStream? {
            val jar = Burp.openBurpJar() ?: return null
            return getResourceFromJar(jar, path)
        }

        public fun getBurpDataDir(): String? {
            val os = System.getProperty("os.name").lowercase()
            val dataDir = if (os.contains("win")) {
                File(System.getenv("APPDATA"), "BurpSuite")
            } else {
                File(System.getProperty("user.home"), ".BurpSuite")
            }
            return if (dataDir.isDirectory) {
                dataDir.absolutePath
            } else {
                null
            }
        }
    }
}
