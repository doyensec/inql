package burp

import inql.ui.Icon
import java.awt.Image
import java.util.zip.ZipFile
import javax.imageio.ImageIO

class BurpIcons private constructor() {
    enum class BurpIcon {
        CLOSE,
        CONFIG,
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
    }

    private val burpJar: ZipFile? = Burp.openBurpJar()

    private fun getRawImage(path: String): Image? {
        if (burpJar == null) return null
        val inputStream = Burp.getResourceFromJar(burpJar, path) ?: return null
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
        if (Burp.isDarkMode()) basePath += "/dark"
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
