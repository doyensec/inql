package burp

import com.google.gson.Gson
import com.google.gson.JsonObject
import inql.Config
import inql.Logger
import java.awt.Desktop
import java.io.File
import java.net.URI
import java.util.*

class Browser {

    companion object {
        // A Burp browser version directory is named like "119.0.6045.159".
        private val VERSION_DIR_REGEX = Regex("^\\d+(\\.\\d+)+\$")

        /**
         * All directories where Burp may have placed its embedded browser ("burpbrowser"),
         * depending on how Burp was installed. We search every one of them rather than
         * committing to the first that merely exists, because an empty/stale "burpbrowser"
         * folder in one location must not stop us from finding the real browser in another.
         */
        private fun getBrowserSearchRoots(): List<File> {
            val roots = mutableListOf<File>()

            // Next to the Burp jar (standalone / installer layouts that co-locate the browser)
            Burp.findBurpJarPath()?.let { File(it).parentFile }?.let { roots.add(File(it, "burpbrowser")) }

            // Burp's data directory (~/.BurpSuite on *nix, %APPDATA%/BurpSuite on Windows)
            Burp.getBurpDataDir()?.let { roots.add(File(it, "burpbrowser")) }

            // Default PortSwigger installer locations under the user's home directory
            System.getProperty("user.home")?.let { home ->
                for (name in listOf("BurpSuitePro", "BurpSuiteCommunity", ".BurpSuite")) {
                    roots.add(File(home, "$name${File.separator}burpbrowser"))
                }
            }

            return roots.filter { it.isDirectory }.distinctBy { it.absolutePath }
        }

        /**
         * Locate the browser executable inside a single version directory. The binary name and
         * nesting differ per OS. On macOS the bundle name is NOT hard-coded: Burp historically
         * shipped "Chromium.app" but renamed the embedded browser to "Burp Browser" in Burp Suite
         * 2026.7.2, so we scan for any .app bundle and return its executable.
         */
        private fun getBrowserExecutableInVersionDir(versionDir: File): File? {
            val os = System.getProperty("os.name").lowercase()
            return when {
                os.contains("win") -> File(versionDir, "chrome.exe").takeIf { it.isFile }
                os.contains("mac") -> {
                    val macOsDir = versionDir.listFiles { f -> f.isDirectory && f.name.endsWith(".app") }
                        ?.map { File(it, "Contents${File.separator}MacOS") }
                        ?.firstOrNull { it.isDirectory }
                        ?: return null
                    macOsDir.listFiles { f -> f.isFile && f.canExecute() }?.firstOrNull()
                }
                else -> File(versionDir, "chrome").takeIf { it.isFile }
            }
        }

        /** Parse a version directory name ("119.0.6045.159") into comparable numeric segments. */
        private fun versionDirFor(executable: File): File? {
            var dir: File? = executable.parentFile
            while (dir != null) {
                if (dir.name.matches(VERSION_DIR_REGEX)) return dir
                dir = dir.parentFile
            }
            return null
        }

        private fun versionSortKey(executable: File): List<Int> =
            versionDirFor(executable)?.name?.split(".")?.mapNotNull { it.toIntOrNull() } ?: emptyList()

        private val versionComparator = Comparator<File> { a, b ->
            val va = versionSortKey(a)
            val vb = versionSortKey(b)
            for (i in 0 until maxOf(va.size, vb.size)) {
                val diff = va.getOrElse(i) { 0 } - vb.getOrElse(i) { 0 }
                if (diff != 0) return@Comparator diff
            }
            0
        }

        fun getInternalBrowserPath(): String? {
            val candidates = mutableListOf<File>()
            for (root in getBrowserSearchRoots()) {
                val versionDirs = root.listFiles { f -> f.isDirectory } ?: continue
                for (versionDir in versionDirs) {
                    getBrowserExecutableInVersionDir(versionDir)?.let { candidates.add(it) }
                }
            }

            if (candidates.isEmpty()) {
                Logger.debug("Cannot find Burp's embedded browser executable in any known location")
                return null
            }

            // Prefer the highest version (compared numerically, not lexicographically)
            return candidates.maxWithOrNull(versionComparator)?.absolutePath
        }

        private fun getChromiumVersionFromPath(path: String): String? {
            // Expected version dir name like 119.0.6045.159
            return versionDirFor(File(path))?.name
        }

        private fun getBurpProxyPort(): Int {
            try {
                val json = Burp.Montoya.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")
                val settings = Gson().fromJson(json, JsonObject::class.java)
                val listeners = settings.get("proxy").asJsonObject.get("request_listeners").asJsonArray
                for (listener in listeners.map { it.asJsonObject }) {
                    if (listener.get("running").asBoolean && !listener.has("redirect_to_host")) { // Get non-redirecting proxy ports only
                        val port = listener.get("listener_port").asInt
                        Logger.debug("Found Burp Proxy port: $port")
                        return port
                    }
                }
                Logger.warning("Cannot find a valid proxy port, defaulting to 8080")
                return 8080
            } catch (e: Exception) {
                Logger.warning("Failed to determine Burp's proxy port, defaulting to 8080")
                return 8080
            }
        }

        fun getChromiumArgs(path: String): List<String> {
            val dataDir = Burp.getBurpDataDir()
            val args = mutableListOf(
                "--disable-ipc-flooding-protection",
                "--disable-xss-auditor",
                "--disable-bundled-ppapi-flash",
                "--disable-plugins-discovery",
                "--disable-default-apps",
                "--disable-prerender-local-predictor",
                "--disable-sync",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--disable-prerender-local-predictor",
                "--disk-cache-size=0",
                "--disable-settings-window",
                "--disable-notifications",
                "--disable-speech-api",
                "--disable-file-system",
                "--disable-presentation-api",
                "--disable-permissions-api",
                "--disable-new-zip-unpacker",
                "--disable-media-session-api",
                "--no-experiments",
                "--no-events",
                "--no-first-run",
                "--no-default-browser-check",
                "--no-pings",
                "--no-service-autorun",
                "--media-cache-size=0",
                "--use-fake-device-for-media-stream",
                "--dbus-stub",
                "--disable-background-networking",
                "--disable-features=ChromeWhatsNewUI,HttpsUpgrades",
                "--proxy-server=localhost:${getBurpProxyPort()}",
                "--proxy-bypass-list=<-loopback>",
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getChromiumVersionFromPath(path)} Safari/537.36",
                "--ignore-certificate-errors",
            )

            val userDataDir = "${dataDir}/pre-wired-browser"
            val extDir = "${dataDir}/burp-chromium-extension"

            if (File(userDataDir).isDirectory) {
                args.add("--user-data-dir=$userDataDir")
            }
            if (File(extDir).isDirectory) {
                args.add("--load-extension=$extDir")
            }
            if (System.getProperty("user.name") == "root") {
                args.add("--no-sandbox")
            }
            return args
        }

        fun launchEmbedded(_uri: String): Boolean {
            val uri = if (_uri.startsWith("http")) _uri else "https://${_uri}"
            val pb = ProcessBuilder()

            val executable = this.getInternalBrowserPath() ?: return false
            val args = this.getChromiumArgs(executable)
            pb.command(
                executable,
                *args.toTypedArray(),
                uri
            )
            try {
                pb.start()
            } catch (e: Exception) {
                Logger.error("Error launching embedded browser: ${e.javaClass.name}")
                e.message?.let { Logger.error(it) }
                return false
            }
            Logger.debug("Embedded browser launched successfully")
            return true
        }

        fun launchExternal(_uri: String): Boolean {
            val uri = if (_uri.startsWith("http")) _uri else "https://${_uri}"
            val customCommand = Config.getInstance().getString("integrations.browser.external.command") ?: ""

            if (customCommand.isEmpty() && Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI(uri))
                return true
            } else {
                val pb = ProcessBuilder()
                val os = System.getProperty("os.name").lowercase()
                if (customCommand.isNotEmpty()) {
                    val args = ArrayList<String>()
                    StringTokenizer(customCommand).asIterator().forEachRemaining { it -> args.add(it as String) }
                    pb.command(args)
                }
                if (os.contains("win")) {
                    pb.command("rundll32", "url.dll,FileProtocolHandler", uri)
                } else if (os.contains("mac")) {
                    pb.command("open", "-u", uri)
                } else if (os.contains("nix") || os.contains("nux")) {
                    pb.command("xdg-open", uri)
                }
                try {
                    pb.start()
                } catch (e: Exception) {
                    Logger.error("Error launching external browser: ${e.javaClass.name}")
                    e.message?.let { Logger.error(it) }
                    return false
                }
                Logger.debug("External browser launched successfully")
                return true
            }
        }
    }
}