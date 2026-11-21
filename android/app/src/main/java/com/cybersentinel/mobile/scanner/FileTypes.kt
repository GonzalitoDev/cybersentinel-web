package com.cybersentinel.mobile.scanner

/** Tipo REAL de un archivo, determinado por su contenido (firma de bytes), no por su extensión. */
enum class RealType(val label: String, val executable: Boolean = false, val archive: Boolean = false) {
    APK("Paquete Android (APK)", executable = true, archive = true),
    DEX("Código ejecutable Android (DEX)", executable = true),
    ELF("Binario ejecutable Linux/Android (ELF)", executable = true),
    PE("Ejecutable de Windows (EXE/DLL)", executable = true),
    JAR("Archivo Java (JAR)", executable = true, archive = true),
    SCRIPT("Script ejecutable (#!)"),
    ZIP("Archivo comprimido ZIP", archive = true),
    OOXML("Documento de Office (DOCX/XLSX/PPTX)", archive = true),
    OLE2("Documento de Office antiguo (DOC/XLS/PPT)"),
    PDF("Documento PDF"),
    RAR("Archivo comprimido RAR", archive = true),
    SEVEN_Z("Archivo comprimido 7z", archive = true),
    GZIP("Archivo comprimido GZIP", archive = true),
    PNG("Imagen PNG"),
    JPEG("Imagen JPEG"),
    GIF("Imagen GIF"),
    WEBP("Imagen WebP"),
    BMP("Imagen BMP"),
    ISO_MEDIA("Audio/video/imagen ISO (MP4/M4A/3GP/HEIC)"),
    MP3("Audio MP3"),
    OGG("Audio OGG/Opus"),
    WAV("Audio WAV"),
    AVI("Video AVI"),
    MATROSKA("Video MKV/WebM"),
    HTML("Página HTML"),
    TEXT("Texto"),
    EMPTY("Archivo vacío"),
    UNKNOWN("Desconocido");
}

object FileTypes {

    /** Extensiones que el usuario percibe como "documento o multimedia" (inofensivas a la vista). */
    val DOC_MEDIA_EXT = setOf(
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv",
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif", "svg",
        "mp3", "m4a", "aac", "ogg", "opus", "wav", "flac", "amr",
        "mp4", "3gp", "mkv", "webm", "mov", "avi"
    )

    /** Extensiones de ejecutables o instaladores. */
    val EXECUTABLE_EXT = setOf(
        "apk", "xapk", "apks", "apkm", "dex", "so", "jar",
        "exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "vbs", "vbe", "js", "jse", "wsf", "ps1", "hta", "lnk",
        "sh", "elf"
    )

    /** Tipos esperados según extensión. Si la extensión no está aquí, no se evalúa coincidencia. */
    private val EXPECTED: Map<String, Set<RealType>> = mapOf(
        "pdf" to setOf(RealType.PDF),
        "jpg" to setOf(RealType.JPEG), "jpeg" to setOf(RealType.JPEG),
        "png" to setOf(RealType.PNG), "gif" to setOf(RealType.GIF), "webp" to setOf(RealType.WEBP),
        "bmp" to setOf(RealType.BMP),
        "heic" to setOf(RealType.ISO_MEDIA), "heif" to setOf(RealType.ISO_MEDIA),
        "mp4" to setOf(RealType.ISO_MEDIA), "m4a" to setOf(RealType.ISO_MEDIA), "3gp" to setOf(RealType.ISO_MEDIA),
        "mov" to setOf(RealType.ISO_MEDIA),
        "mp3" to setOf(RealType.MP3), "ogg" to setOf(RealType.OGG), "opus" to setOf(RealType.OGG),
        "wav" to setOf(RealType.WAV), "avi" to setOf(RealType.AVI),
        "mkv" to setOf(RealType.MATROSKA), "webm" to setOf(RealType.MATROSKA),
        "docx" to setOf(RealType.OOXML), "xlsx" to setOf(RealType.OOXML), "pptx" to setOf(RealType.OOXML),
        "docm" to setOf(RealType.OOXML), "xlsm" to setOf(RealType.OOXML), "pptm" to setOf(RealType.OOXML),
        "doc" to setOf(RealType.OLE2), "xls" to setOf(RealType.OLE2), "ppt" to setOf(RealType.OLE2),
        "zip" to setOf(RealType.ZIP, RealType.OOXML, RealType.JAR, RealType.APK),
        "apk" to setOf(RealType.APK),
        "jar" to setOf(RealType.JAR, RealType.ZIP),
        "dex" to setOf(RealType.DEX),
        "exe" to setOf(RealType.PE), "dll" to setOf(RealType.PE), "scr" to setOf(RealType.PE),
        "rar" to setOf(RealType.RAR), "7z" to setOf(RealType.SEVEN_Z),
        "gz" to setOf(RealType.GZIP), "tgz" to setOf(RealType.GZIP),
        "txt" to setOf(RealType.TEXT, RealType.EMPTY), "csv" to setOf(RealType.TEXT, RealType.EMPTY),
        "html" to setOf(RealType.HTML, RealType.TEXT), "htm" to setOf(RealType.HTML, RealType.TEXT)
    )

    fun extensionOf(name: String): String {
        val dot = name.lastIndexOf('.')
        return if (dot <= 0 || dot == name.length - 1) "" else name.substring(dot + 1).trim().lowercase()
    }

    fun expectedTypes(ext: String): Set<RealType>? = EXPECTED[ext]

    /** Detecta el tipo por la firma (magic bytes) de los primeros bytes del archivo. */
    fun detect(header: ByteArray, length: Int): RealType {
        if (length <= 0) return RealType.EMPTY
        fun at(off: Int, vararg b: Int): Boolean {
            if (off + b.size > length) return false
            for (i in b.indices) if ((header[off + i].toInt() and 0xFF) != b[i]) return false
            return true
        }
        fun ascii(off: Int, s: String): Boolean = at(off, *s.map { it.code }.toIntArray())

        return when {
            at(0, 0x50, 0x4B, 0x03, 0x04) || at(0, 0x50, 0x4B, 0x05, 0x06) -> RealType.ZIP // se refina luego
            ascii(0, "dex\n") -> RealType.DEX
            at(0, 0x7F, 0x45, 0x4C, 0x46) -> RealType.ELF
            ascii(0, "MZ") && length >= 64 -> RealType.PE
            ascii(0, "%PDF") -> RealType.PDF
            at(0, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1) -> RealType.OLE2
            ascii(0, "Rar!") -> RealType.RAR
            at(0, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C) -> RealType.SEVEN_Z
            at(0, 0x1F, 0x8B) -> RealType.GZIP
            at(0, 0x89, 0x50, 0x4E, 0x47) -> RealType.PNG
            at(0, 0xFF, 0xD8, 0xFF) -> RealType.JPEG
            ascii(0, "GIF8") -> RealType.GIF
            ascii(0, "RIFF") && ascii(8, "WEBP") -> RealType.WEBP
            ascii(0, "RIFF") && ascii(8, "WAVE") -> RealType.WAV
            ascii(0, "RIFF") && ascii(8, "AVI ") -> RealType.AVI
            ascii(4, "ftyp") -> RealType.ISO_MEDIA
            ascii(0, "ID3") || (length > 1 && (header[0].toInt() and 0xFF) == 0xFF && (header[1].toInt() and 0xE0) == 0xE0) -> RealType.MP3
            ascii(0, "OggS") -> RealType.OGG
            at(0, 0x1A, 0x45, 0xDF, 0xA3) -> RealType.MATROSKA
            ascii(0, "BM") && length > 26 -> RealType.BMP
            ascii(0, "#!") -> RealType.SCRIPT
            else -> textOrUnknown(header, length)
        }
    }

    private fun textOrUnknown(header: ByteArray, length: Int): RealType {
        val n = minOf(length, 1024)
        var printable = 0
        for (i in 0 until n) {
            val b = header[i].toInt() and 0xFF
            if (b == 9 || b == 10 || b == 13 || b in 32..126 || b >= 0x80) printable++
            else if (b == 0) return RealType.UNKNOWN
        }
        if (printable < n * 0.95) return RealType.UNKNOWN
        val start = String(header, 0, minOf(n, 512), Charsets.UTF_8).trimStart().lowercase()
        return if (start.startsWith("<!doctype html") || start.startsWith("<html")) RealType.HTML else RealType.TEXT
    }
}
