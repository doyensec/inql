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
        private fun getChromiumExecutableNameForOS(): String {
            val os = System.getProperty("os.name").lowercase()
            return  if (os.contains("win")) {
                "chrome.exe"
            } else if (os.contains("mac")) {
                "Chromium.app/Contents/MacOS/Chromium"
            } else {
                "chrome"
            }
        }
        public fun getInternalBrowserPath(): String? {
            val executableName: String = getChromiumExecutableNameForOS()

            // Check in Burp jar's folder
            val burpPath = Burp.findBurpJarPath()?.let { File(it) } ?: return null
            var browserDir = File(burpPath.parent, "burpbrowser")
            if (!browserDir.isDirectory) {
                // Search in the data directory instead
                browserDir = File(Burp.getBurpDataDir(), "burpbrowser")
                if (!browserDir.isDirectory) {
                    Logger.debug("Cannot find chromium")
                    return null
                }
            }

            val versions = browserDir.listFiles { it -> it.isDirectory && File(it, executableName).isFile }

            if (versions == null || versions.isEmpty()) {
                Logger.debug("Cannot find chromium executable in burpbrowser dir")
                return null
            }

            // Take latest version if multiple
            versions.sortDescending()
            return File(versions.first(), executableName).absolutePath
        }

        private fun getChromiumVersionFromPath(path: String): String? {
            val executableName: String = getChromiumExecutableNameForOS()
            val directory = File(path.removeSuffix(executableName))
            // Expected string like 119.0.6045.159
            if (directory.isDirectory && directory.name.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+\$"))) {
                return directory.name
            }
            return null
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

        public fun getChromiumArgs(path: String): List<String> {
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

            return args
        }

        public fun launchEmbedded(_uri: String): Boolean {
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

        public fun launchExternal(_uri: String): Boolean {
            val uri = if (_uri.startsWith("http")) _uri else "https://${_uri}"
            val customCommand = Config.getInstance().getString("integrations.browser.external.command") ?: ""

            if (customCommand.isEmpty() && Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI(uri));
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