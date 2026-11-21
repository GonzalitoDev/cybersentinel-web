package com.cybersentinel.mobile.scanner

import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.Signature
import com.cybersentinel.mobile.scanner.Hashing.toHex
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

/** Resultado de leer el contenido de un archivo en UNA sola pasada. */
class ContentReport(
    val realType: RealType,
    val sha256: String?,
    val patterns: Set<String>,
    val isEicar: Boolean
)

object ContentReader {

    const val PATTERN_SCAN_LIMIT = 16L * 1024 * 1024

    private const val EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"

    private fun utf16(s: String) = s.toByteArray(Charsets.UTF_16LE)

    private val PDF_PATTERNS = mapOf(
        "pdf_js" to "/JavaScript".toByteArray(),
        "pdf_launch" to "/Launch".toByteArray(),
        "pdf_embedded" to "/EmbeddedFile".toByteArray()
    )
    private val OLE_PATTERNS = mapOf(
        "ole_vba" to utf16("_VBA_PROJECT"),
        "ole_macros" to utf16("Macros")
    )

    fun read(open: () -> InputStream, size: Long, hashLimit: Long, isCancelled: () -> Boolean): ContentReport {
        val doHash = size in 0..hashLimit
        val md = if (doHash) MessageDigest.getInstance("SHA-256") else null
        val found = HashSet<String>()
        var type = RealType.UNKNOWN
        var isEicar = false

        open().use { s ->
            val header = ByteArray(8192)
            var hl = 0
            while (hl < header.size) {
                val n = s.read(header, hl, header.size - hl)
                if (n < 0) break
                hl += n
            }
            md?.update(header, 0, hl)
            type = FileTypes.detect(header, hl)

            if (size in 68..128 && hl >= 68) {
                val txt = String(header, 0, hl, Charsets.ISO_8859_1)
                if (txt.startsWith(EICAR) && txt.substring(EICAR.length).isBlank()) isEicar = true
            }

            val patterns = when (type) {
                RealType.PDF -> PDF_PATTERNS
                RealType.OLE2 -> OLE_PATTERNS
                else -> emptyMap()
            }
            searchAll(header, hl, patterns, found)

            if (md != null || patterns.isNotEmpty()) {
                val maxPat = patterns.values.maxOfOrNull { it.size } ?: 1
                val buf = ByteArray(64 * 1024)
                var carry = header.copyOfRange(maxOf(0, hl - (maxPat - 1)), hl)
                var total = hl.toLong()
                while (true) {
                    if (isCancelled()) throw CancellationException("cancelado")
                    val scanning = patterns.isNotEmpty() && total < PATTERN_SCAN_LIMIT && found.size < patterns.size
                    if (md == null && !scanning) break
                    val n = s.read(buf)
                    if (n < 0) break
                    md?.update(buf, 0, n)
                    if (scanning) {
                        val combined = ByteArray(carry.size + n)
                        System.arraycopy(carry, 0, combined, 0, carry.size)
                        System.arraycopy(buf, 0, combined, carry.size, n)
                        searchAll(combined, combined.size, patterns, found)
                        carry = combined.copyOfRange(maxOf(0, combined.size - (maxPat - 1)), combined.size)
                    }
                    total += n
                }
            }
        }
        return ContentReport(type, md?.digest()?.toHex(), found, isEicar)
    }

    private fun searchAll(data: ByteArray, len: Int, patterns: Map<String, ByteArray>, found: MutableSet<String>) {
        for ((key, p) in patterns) {
            if (key in found) continue
            if (indexOf(data, len, p) >= 0) found.add(key)
        }
    }

    private fun indexOf(data: ByteArray, len: Int, p: ByteArray): Int {
        if (p.isEmpty() || len < p.size) return -1
        outer@ for (i in 0..len - p.size) {
            for (j in p.indices) if (data[i + j] != p[j]) continue@outer
            return i
        }
        return -1
    }
}

/** Información de las entradas de un ZIP (para distinguir APK, JAR, Office, etc.). */
class ZipInfo(val refinedType: RealType, val hasMacros: Boolean, val nestedExecutables: List<String>, val entryCount: Int)

object ZipInspector {
    private const val MAX_ENTRIES = 5000

    fun inspectFile(file: File): ZipInfo? = runCatching {
        ZipFile(file).use { z ->
            val names = ArrayList<String>()
            val e = z.entries()
            while (e.hasMoreElements() && names.size < MAX_ENTRIES) names.add(e.nextElement().name)
            classify(names)
        }
    }.getOrNull()

    fun inspectStream(input: InputStream, isCancelled: () -> Boolean): ZipInfo? = runCatching {
        ZipInputStream(input).use { z ->
            val names = ArrayList<String>()
            while (names.size < MAX_ENTRIES) {
                if (isCancelled()) throw CancellationException("cancelado")
                val entry = z.nextEntry ?: break
                names.add(entry.name)
            }
            classify(names)
        }
    }.getOrNull()

    private fun classify(names: List<String>): ZipInfo {
        val hasManifest = names.any { it == "AndroidManifest.xml" }
        val hasDex = names.any { it.matches(Regex("classes\\d*\\.dex")) }
        val hasContentTypes = names.any { it == "[Content_Types].xml" }
        val hasJarManifest = names.any { it.equals("META-INF/MANIFEST.MF", ignoreCase = true) }
        val hasClass = names.any { it.endsWith(".class") }
        val macros = names.any { it.endsWith("vbaProject.bin", ignoreCase = true) }
        val nested = names.filter {
            val ext = FileTypes.extensionOf(it.substringAfterLast('/'))
            ext in setOf("apk", "dex", "exe", "scr", "bat", "cmd", "vbs", "js", "jar", "msi", "ps1", "hta")
        }.take(20)
        val type = when {
            hasManifest && hasDex -> RealType.APK
            hasContentTypes -> RealType.OOXML
            hasJarManifest && hasClass -> RealType.JAR
            else -> RealType.ZIP
        }
        return ZipInfo(type, macros, nested, names.size)
    }
}

/** Contexto de un archivo para las reglas. */
class FileContext(
    val name: String,
    val displayPath: String,
    val size: Long,
    val content: ContentReport?,
    val realType: RealType,
    val zip: ZipInfo?,
    val apkVerdict: Pair<AppFacts, Verdict>?,
    val signature: Signature?,
    val trusted: Boolean,
    val readError: String?
)

data class FileVerdict(val level: RiskLevel, val title: String, val reasons: List<String>)

object FileRules {

    private val MEDIA_FOLDERS = setOf(
        "dcim", "pictures", "music", "movies", "ringtones", "alarms", "notifications", "podcasts", "audiobooks", "recordings"
    )
    private val BIDI = Regex("[\\u202A-\\u202E\\u2066-\\u2069\\u200E\\u200F]")
    private val INVISIBLE = Regex("[\\u200B-\\u200D\\uFEFF\\u00AD\\p{Cc}]")
    private val CYRILLIC_GREEK = Regex("[\\u0370-\\u03FF\\u0400-\\u04FF]")
    private val LATIN = Regex("[A-Za-z]")

    fun evaluate(c: FileContext): FileVerdict {
        var level = RiskLevel.SAFE
        var title = "Sin indicadores de amenaza"
        val reasons = mutableListOf<String>()
        fun add(l: RiskLevel, t: String, text: String) {
            if (l.weight > level.weight) { level = l; title = t }
            reasons += "[${l.label}] $text"
        }

        val ext = FileTypes.extensionOf(c.name)
        val segments = c.displayPath.split('/').filter { it.isNotEmpty() }
        val parents = segments.dropLast(1)
        val inHiddenFolder = parents.drop(1).any { it.startsWith(".") }
        val isHidden = c.name.startsWith(".")
        val real = c.realType

        // --- Amenazas confirmadas
        c.signature?.let { add(RiskLevel.CRITICAL, "Amenaza confirmada", "El SHA-256 coincide con una firma conocida: ${it.name} (fuente: ${it.source}).") }
        if (c.content?.isEicar == true && c.signature == null) {
            add(RiskLevel.CRITICAL, "Archivo de prueba EICAR", "Contiene la cadena de prueba EICAR. Es inofensivo: se usa para comprobar que un antivirus funciona.")
        }
        c.apkVerdict?.second?.let { v -> if (v.level == RiskLevel.CRITICAL && c.signature == null) add(RiskLevel.CRITICAL, "Amenaza confirmada", "El APK coincide con una firma conocida.") }

        // --- Extensión engañosa (tipo real distinto del que aparenta)
        val expected = FileTypes.expectedTypes(ext)
        if (real.executable) {
            when {
                ext in FileTypes.DOC_MEDIA_EXT ->
                    add(RiskLevel.HIGH, "Extensión engañosa", "Se presenta como .$ext pero en realidad es ${real.label}.")
                ext.isNotEmpty() && ext !in FileTypes.EXECUTABLE_EXT && expected?.contains(real) != true ->
                    add(RiskLevel.MEDIUM, "Ejecutable con extensión inusual", "Es ${real.label} pero tiene extensión .$ext.")
                ext.isEmpty() && real != RealType.SCRIPT ->
                    add(RiskLevel.MEDIUM, "Ejecutable sin extensión", "Es ${real.label} y no tiene extensión visible.")
            }
        } else if (expected != null && real != RealType.UNKNOWN && real != RealType.EMPTY && real !in expected) {
            if (real.archive && ext in FileTypes.DOC_MEDIA_EXT) {
                add(RiskLevel.LOW, "Contenido no coincide", "Tiene extensión .$ext pero contiene ${real.label}.")
            }
        }

        // --- Nombre
        val parts = c.name.split('.').map { it.trim().lowercase() }
        if (parts.size >= 3) {
            val last = parts.last()
            val prev = parts[parts.size - 2]
            if (last in FileTypes.EXECUTABLE_EXT && prev in FileTypes.DOC_MEDIA_EXT) {
                add(RiskLevel.HIGH, "Doble extensión", "Doble extensión \".$prev.$last\": aparenta ser un documento pero es un ejecutable/instalador.")
            }
        }
        if (Regex("\\s{5,}\\.[A-Za-z0-9]{2,5}$").containsMatchIn(c.name)) {
            add(RiskLevel.MEDIUM, "Extensión escondida con espacios", "Usa muchos espacios antes de la extensión real para ocultarla.")
        }
        if (BIDI.containsMatchIn(c.name)) {
            add(if (real.executable || FileTypes.extensionOf(c.name.replace(BIDI, "")) in FileTypes.EXECUTABLE_EXT) RiskLevel.HIGH else RiskLevel.MEDIUM,
                "Nombre con inversión de texto", "Contiene caracteres de control de dirección (RLO), usados para invertir y disfrazar la extensión.")
        }
        if (INVISIBLE.containsMatchIn(c.name)) {
            add(RiskLevel.LOW, "Nombre con caracteres invisibles", "El nombre contiene caracteres invisibles o de control.")
        }
        if (CYRILLIC_GREEK.containsMatchIn(c.name) && LATIN.containsMatchIn(c.name)) {
            add(RiskLevel.LOW, "Nombre con letras que imitan otras", "Mezcla letras latinas con cirílicas/griegas que se ven iguales (posible imitación).")
        }
        if (c.name.length > 150) add(RiskLevel.LOW, "Nombre muy largo", "El nombre tiene ${c.name.length} caracteres.")

        // --- Ubicación
        if (real.executable && real != RealType.SCRIPT) {
            if (isHidden || inHiddenFolder) {
                add(RiskLevel.HIGH, "Ejecutable oculto", "Es ${real.label} y está ${if (isHidden) "oculto" else "dentro de una carpeta oculta"}.")
            }
            val mediaFolder = parents.firstOrNull { it.lowercase() in MEDIA_FOLDERS }
            if (mediaFolder != null) {
                add(RiskLevel.MEDIUM, "Ejecutable en ubicación inusual", "Es ${real.label} y está en la carpeta \"$mediaFolder\", que normalmente sólo contiene fotos, música o videos.")
            }
        }

        // --- Contenido
        when (real) {
            RealType.PDF -> {
                val p = c.content?.patterns ?: emptySet()
                if ("pdf_launch" in p) add(RiskLevel.MEDIUM, "PDF con acción de ejecución", "El PDF contiene una acción /Launch, que puede intentar abrir programas.")
                if ("pdf_js" in p) add(RiskLevel.MEDIUM, "PDF con JavaScript", "El PDF contiene código JavaScript.")
                if ("pdf_embedded" in p) add(RiskLevel.LOW, "PDF con archivos adjuntos", "El PDF tiene archivos incrustados.")
            }
            RealType.OLE2 -> {
                val p = c.content?.patterns ?: emptySet()
                if ("ole_vba" in p || "ole_macros" in p) add(RiskLevel.MEDIUM, "Documento con macros", "El documento de Office contiene macros (VBA). Abrilo sólo si confiás en el remitente.")
            }
            RealType.OOXML -> if (c.zip?.hasMacros == true) add(RiskLevel.MEDIUM, "Documento con macros", "El documento de Office contiene macros (vbaProject.bin).")
            RealType.PE -> add(RiskLevel.LOW, "Ejecutable de Windows", "Es un programa de Windows: no funciona en Android, pero podría infectar una PC si lo copiás.")
            RealType.ELF -> add(RiskLevel.MEDIUM, "Binario nativo", "Es un binario ejecutable nativo en el almacenamiento compartido, algo poco habitual.")
            RealType.DEX -> add(RiskLevel.MEDIUM, "Código Android suelto", "Es código ejecutable de Android (DEX) fuera de una app instalada.")
            RealType.SCRIPT -> add(RiskLevel.LOW, "Script", "Es un script ejecutable (#!). Revisá su origen antes de ejecutarlo.")
            else -> {}
        }
        c.zip?.nestedExecutables?.takeIf { it.isNotEmpty() && real != RealType.APK }?.let {
            add(RiskLevel.LOW, "Comprimido con ejecutables", "Contiene ejecutables o instaladores: ${it.take(5).joinToString(", ")}${if (it.size > 5) "…" else ""}.")
        }

        // --- APK: reglas de aplicaciones sobre el paquete
        c.apkVerdict?.let { (facts, verdict) ->
            reasons += "Paquete: ${facts.packageName}${facts.versionName?.let { " (versión $it)" } ?: ""} — nombre: \"${facts.label}\""
            for (r in verdict.reasons) reasons += r
            if (verdict.level.weight > level.weight) { level = verdict.level; title = "APK sospechoso" }
        }
        if (real == RealType.APK && c.apkVerdict == null) {
            add(RiskLevel.LOW, "Instalador APK", "Instalador APK fuera de una tienda (no se pudo leer su manifiesto). Instalalo sólo si conocés el origen.")
        }

        if (c.readError != null) reasons += "No se pudo leer el contenido completo: ${c.readError}"

        if (c.trusted && level != RiskLevel.CRITICAL && level != RiskLevel.SAFE) {
            reasons += "Marcado como confiable por vos: no cuenta para el nivel de riesgo."
            level = RiskLevel.SAFE
            title = "Marcado como confiable"
        }
        if (level == RiskLevel.SAFE && isHidden) title = "Archivo oculto"
        return FileVerdict(level, title, reasons)
    }
}
