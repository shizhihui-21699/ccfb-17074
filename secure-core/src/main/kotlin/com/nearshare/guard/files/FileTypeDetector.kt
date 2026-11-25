package com.nearshare.guard.files

/**
 * 基于内容魔数的文件类型嗅探。
 *
 * 攻击场景中，攻击者把恶意 APK 改名为 "合同文档.pdf" 诱导点击。
 * 因此接收侧**绝不信任**文件名/扩展名/MIME 声明，只检查文件头魔数，
 * 并把"扩展名宣称的类型"与"内容实际类型"做一致性比对。
 */
object FileTypeDetector {

    /** 嗅探只需要前 16 字节即可覆盖全部已识别格式。 */
    const val SNIFF_HEADER_SIZE = 16

    fun sniff(header: ByteArray, declaredName: String? = null): FileDetection {
        val category = detectCategory(header)
        val declaredExt = declaredName?.substringAfterLast('.', "")?.lowercase()
        val extMatches = declaredExt == null || matchesExtension(category, declaredExt)
        return FileDetection(
            category = category,
            declaredExtension = declaredExt,
            extensionMismatch = !extMatches,
            executable = category.executable
        )
    }

    /**
     * 接收侧完整判定：先做头部魔数嗅探；若为 ZIP 容器，再由调用方提供
     * zip 条目列表确认是否为 APK（[identifyApk]）。这是真实设备上
     * 拦截"伪装成文档的恶意安装包"的入口。
     */
    fun detect(header: ByteArray, declaredName: String?, zipEntryNames: List<String>?): FileDetection {
        val initial = sniff(header, declaredName)
        if (initial.category == FileCategory.ARCHIVE &&
            zipEntryNames != null && identifyApk(zipEntryNames)
        ) {
            return initial.copy(
                category = FileCategory.ANDROID_PACKAGE,
                executable = true
            )
        }
        return initial
    }

    @Suppress("ComplexMethod")
    private fun detectCategory(h: ByteArray): FileCategory {
        if (h.size < 4) return FileCategory.GENERIC

        // ZIP 家族：APK / docx / xlsx / pptx / 普通 zip 共享 PK 魔数
        if (startsWith(h, 0x50, 0x4B, 0x03, 0x04) || startsWith(h, 0x50, 0x4B, 0x05, 0x06)) {
            return FileCategory.ARCHIVE // APK 的进一步识别见 [identifyApk]
        }
        // Android DEX
        if (h.size >= 4 && startsWith(h, 'd'.code, 'e'.code, 'x'.code, '\n'.code)) {
            return FileCategory.ANDROID_PACKAGE
        }
        // ELF
        if (startsWith(h, 0x7F, 'E'.code, 'L'.code, 'F'.code)) {
            return FileCategory.ELF_EXECUTABLE
        }
        // PE / DLL
        if (startsWith(h, 'M'.code, 'Z'.code)) {
            return FileCategory.PE_EXECUTABLE
        }
        // PDF
        if (h.size >= 5 && startsWith(h, '%'.code, 'P'.code, 'D'.code, 'F'.code)) {
            return FileCategory.PDF
        }
        // PNG
        if (startsWith(h, 0x89, 'P'.code, 'N'.code, 'G'.code)) return FileCategory.IMAGE
        // JPEG
        if (startsWith(h, 0xFF, 0xD8, 0xFF)) return FileCategory.IMAGE
        // GIF
        if (startsWith(h, 'G'.code, 'I'.code, 'F'.code, '8'.code)) return FileCategory.IMAGE
        // WebP / 其它 RIFF
        if (h.size >= 12 && startsWith(h, 'R'.code, 'I'.code, 'F'.code, 'F'.code)) {
            val webp = h[8] == 'W'.code.toByte() && h[9] == 'E'.code.toByte() &&
                h[10] == 'B'.code.toByte() && h[11] == 'P'.code.toByte()
            return if (webp) FileCategory.IMAGE else FileCategory.GENERIC
        }
        // MP4 / MOV（ftyp）
        if (h.size >= 12 && h[4] == 'f'.code.toByte() && h[5] == 't'.code.toByte() &&
            h[6] == 'y'.code.toByte() && h[7] == 'p'.code.toByte()
        ) {
            return FileCategory.VIDEO
        }
        // Matroska / WebM
        if (h.size >= 12 && startsWith(h, 0x1A, 0x45, 0xDF, 0xA3)) return FileCategory.VIDEO
        // MP3（ID3 或帧同步）
        if (startsWith(h, 'I'.code, 'D'.code, '3'.code) ||
            (h[0] == 0xFF.toByte() && (h[1].toInt() and 0xE0) == 0xE0)
        ) {
            return FileCategory.AUDIO
        }
        // OGG
        if (startsWith(h, 'O'.code, 'g'.code, 'g'.code, 'S'.code)) return FileCategory.AUDIO
        // FLAC
        if (startsWith(h, 'f'.code, 'L'.code, 'a'.code, 'C'.code)) return FileCategory.AUDIO
        // 旧版 Office (OLE2 复合文档)
        if (startsWith(h, 0xD0, 0xCF, 0x11, 0xE0)) return FileCategory.OFFICE_DOCUMENT
        // 脚本：以 shebang 或常见解释器指纹开头（文本内容，需更长头部）
        if (startsWith(h, '#'.code, '!'.code, '/'.code)) return FileCategory.SHELL_SCRIPT

        return FileCategory.GENERIC
    }

    /**
     * ZIP 容器内部再区分：调用方在解压/查 zip 目录后用此方法识别 APK。
     * 纯 JVM 模块不引入 zip 解析依赖，Android 集成层负责读取 zip entry，
     * 这里提供判定规则。
     */
    fun identifyApk(zipEntryNames: List<String>): Boolean =
        zipEntryNames.any { it == "AndroidManifest.xml" } &&
            zipEntryNames.any { it == "classes.dex" || it.startsWith("classes") && it.endsWith(".dex") }

    private fun matchesExtension(category: FileCategory, ext: String): Boolean = when (category) {
        FileCategory.IMAGE -> ext in setOf("png", "jpg", "jpeg", "gif", "webp", "bmp", "heic")
        FileCategory.VIDEO -> ext in setOf("mp4", "mov", "mkv", "webm", "3gp")
        FileCategory.AUDIO -> ext in setOf("mp3", "ogg", "flac", "wav", "m4a", "aac")
        FileCategory.PDF -> ext == "pdf"
        FileCategory.OFFICE_DOCUMENT ->
            ext in setOf("doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp")
        FileCategory.ARCHIVE -> ext in setOf("zip", "rar", "7z", "tar", "gz")
        FileCategory.ANDROID_PACKAGE -> ext in setOf("apk", "apks", "xapk", "dex")
        FileCategory.ELF_EXECUTABLE, FileCategory.PE_EXECUTABLE ->
            ext in setOf("exe", "dll", "bin", "so", "elf")
        FileCategory.SHELL_SCRIPT -> ext in setOf("sh", "bash", "zsh", "py", "pl", "rb")
        FileCategory.GENERIC -> true
    }

    private fun startsWith(h: ByteArray, vararg bytes: Int): Boolean {
        if (h.size < bytes.size) return false
        return bytes.indices.all { h[it].toInt() and 0xFF == bytes[it] and 0xFF }
    }
}

data class FileDetection(
    val category: FileCategory,
    val declaredExtension: String?,
    val extensionMismatch: Boolean,
    val executable: Boolean
)
