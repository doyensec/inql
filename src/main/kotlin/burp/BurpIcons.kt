package burp

import burp.api.montoya.ui.Theme
import inql.Logger
import inql.ui.Icon
import java.awt.Image
import java.io.InputStream
import java.util.zip.ZipFile
import javax.imageio.ImageIO

class BurpIcons private constructor() {
    enum class BurpIcon {
        CLOSE,
        CONFIG
    }

    companion object {
        // Exposed icons
        val CLOSE: Icon?
            get() = getIcon(BurpIcon.CLOSE)

        val CONFIG: Icon?
            get() = getIcon(BurpIcon.CONFIG)

        // internal stuff
        private lateinit var instance: BurpIcons

        private val imageCache = mutableMapOf<BurpIcon, Icon?>()

        private fun getIcon(icon: BurpIcon): Icon? {
            if (!imageCache.containsKey(icon)) {
                imageCache[icon] = getInstance().getIcon(icon)
            }
            return imageCache[icon]
        }

        private fun getInstance(): BurpIcons {
            if (!this::instance.isInitialized) this.instance = BurpIcons()
            return this.instance
        }

        private fun isDarkMode(): Boolean = Burp.Montoya.userInterface().currentTheme() == Theme.DARK
        private fun findBurpJar(): ZipFile? {
            try {
                val classPath = System.getProperty("java.class.path", ".")
                val classPathElements =
                    classPath.split(System.getProperty("path.separator").toRegex()).dropLastWhile { it.isEmpty() }

                var burpJar: ZipFile? = null
                for (elem in classPathElements) {
                    try {
                        val zf = ZipFile(elem)

                        if (zf.getEntry("burp/StartBurp.class") != null) {
                            burpJar = zf
                            break
                        }
                        zf.close()
                    } catch (e: Exception) {
                        continue
                    }
                }

                if (burpJar == null) return null
                return burpJar

            } catch (e: Exception) {
                Logger.warning("Cannot find burp jar file for resource loading:")
                Logger.warning(e.toString())
            }
            return null
        }
    }

    private val burpJar: ZipFile? = findBurpJar()

    // https://stackoverflow.com/a/3923182
    private fun getResource(path: String): InputStream? {
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

    private fun getRawImage(path: String): Image? {
        if (burpJar == null) return null
        val inputStream = this.getResource(path) ?: return null
        return ImageIO.read(inputStream)
    }

    private fun getIcon(normal: String, hover: String? = null, selected: String? = null): Icon? {
        val normalImage: Image = this.getRawImage(normal) ?: return null
        var hoverImage: Image? = null
        var selectedImage: Image? = null
        if (hover != null) hoverImage = this.getRawImage(hover)
        if (selected != null) selectedImage = this.getRawImage(selected)
        return Icon(normalImage, hoverImage, selectedImage)
    }

    private fun getIcon(icon: BurpIcon): Icon? {
        var basePath = "resources/Media"
        if (isDarkMode()) basePath += "/dark"
        return when (icon) {
            BurpIcon.CLOSE -> {
                this.getIcon(
                    "$basePath/close.png",
                    "$basePath/close_hover.png",
                    "$basePath/close_pressed.png",
                )
            }

            BurpIcon.CONFIG -> {
                this.getIcon(
                    "$basePath/configuration.png",
                    "$basePath/configuration_hover.png",
                    "$basePath/configuration_selected.png",
                )
            }
        }
    }
}