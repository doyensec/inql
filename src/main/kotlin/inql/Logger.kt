package inql

class Logger {
    companion object {
        private val default = Logger()
        fun debug(msg: String) = default.log(msg, Level.DEBUG)
        fun info(msg: String) = default.log(msg, Level.INFO)
        fun warning(msg: String) = default.log(msg, Level.WARNING)
        fun error(msg: String) = default.log(msg, Level.ERROR)
        fun critical(msg: String) = default.log(msg, Level.CRITICAL)
        fun setLevel(level: Level) {
            default.level = level
        }

        fun setLevel(level: String) {
            default.setLevel(level)
        }
    }

    enum class Level {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL,
    }

    private var level = Level.DEBUG
    fun setLevel(level: Level) {
        this.level = level
    }

    fun setLevel(level: String) {
        setLevel(
            when (level.uppercase()) {
                "DEBUG" -> Level.DEBUG
                "INFO" -> Level.INFO
                "WARNING" -> Level.WARNING
                "ERROR" -> Level.ERROR
                "CRITICAL" -> Level.CRITICAL
                else -> Level.DEBUG
            },
        )
    }

    fun printStackTrace() {
        for ((idx, e) in Thread.currentThread().stackTrace.withIndex()) {
            println("$idx: ${e.fileName}:${e.lineNumber} :: ${e.className}.${e.methodName}")
        }
    }

    private fun log(msg: String, level: Level) {
        if (level < this.level) return

        if (level < Level.WARNING) {
            println(format(msg, level))
        } else {
            System.err.println(format(msg, level))
        }
    }

    fun debug(msg: String) = log(msg, Level.DEBUG)
    fun info(msg: String) = log(msg, Level.INFO)
    fun warning(msg: String) = log(msg, Level.WARNING)
    fun error(msg: String) = log(msg, Level.ERROR)
    fun critical(msg: String) = log(msg, Level.CRITICAL)
    private val _fileName get(): String = Thread.currentThread().stackTrace[6].fileName ?: "null"
    private val _lineNumber get(): Int = Thread.currentThread().stackTrace[6].lineNumber
    private val _fullClassName get(): String = Thread.currentThread().stackTrace[6].className
    private val _shortClassName
        get(): String {
            val fullClass = Thread.currentThread().stackTrace[6].className
            return fullClass.substring(fullClass.lastIndexOf('.') + 1)
        }
    private val _methodName get(): String = Thread.currentThread().stackTrace[6].methodName
    private fun format(msg: String, level: Level? = null): String {
        val prefix = when (level) {
            Level.DEBUG -> "[D]"
            Level.INFO -> "[I]"
            Level.WARNING -> "[W]"
            Level.ERROR -> "[E]"
            Level.CRITICAL -> "[C]"
            else -> ""
        }
        return "$prefix[$_fileName:$_lineNumber :: $_shortClassName.$_methodName()]    $msg"
    }
}
