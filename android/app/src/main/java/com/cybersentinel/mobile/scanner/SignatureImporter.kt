package com.cybersentinel.mobile.scanner

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.cybersentinel.mobile.data.Database
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.util.zip.ZipInputStream

/**
 * Importa firmas SHA-256 desde un archivo elegido por el usuario (sin conexión a Internet).
 * Formatos admitidos:
 *  - .txt con un hash por línea (se ignoran líneas que empiezan con #)
 *  - .csv (por ejemplo, exportaciones de MalwareBazaar: usa las columnas sha256_hash y signature)
 *  - .zip que contenga alguno de los anteriores
 */
class SignatureImporter(private val context: Context) {

    data class Result(val read: Int, val added: Int, val invalidLines: Int, val source: String)

    private val hexToken = Regex("\\b[0-9a-fA-F]{64}\\b")

    fun import(uri: Uri, onProgress: (Int) -> Unit = {}): Result {
        val fileName = displayName(uri) ?: "archivo"
        val source = "Importada: $fileName"
        val db = Database.get(context)
        var read = 0
        var added = 0
        var invalid = 0

        fun consume(input: InputStream) {
            val reader = BufferedReader(InputStreamReader(input, Charsets.UTF_8))
            val batch = ArrayList<Pair<String, String>>(5000)
            var shaCol = -1
            var sigCol = -1
            var typeCol = -1
            while (true) {
                val raw = reader.readLine() ?: break
                val line = raw.trim()
                if (line.isEmpty()) continue
                if (line.startsWith("#")) {
                    // Encabezado comentado de MalwareBazaar: # "first_seen_utc","sha256_hash",...
                    if (line.contains("sha256_hash")) {
                        val cols = splitCsv(line.removePrefix("#").trim())
                        shaCol = cols.indexOf("sha256_hash")
                        sigCol = cols.indexOf("signature")
                        typeCol = cols.indexOf("file_type_guess")
                    }
                    continue
                }
                if (line.contains("sha256_hash") && shaCol < 0) {
                    val cols = splitCsv(line)
                    shaCol = cols.indexOf("sha256_hash"); sigCol = cols.indexOf("signature"); typeCol = cols.indexOf("file_type_guess")
                    continue
                }
                var hash: String? = null
                var name = "Malware conocido ($fileName)"
                if (shaCol >= 0) {
                    val cols = splitCsv(line)
                    hash = cols.getOrNull(shaCol)?.takeIf { Hashing.isSha256(it) }
                    val sig = cols.getOrNull(sigCol)?.takeIf { it.isNotBlank() && it != "n/a" }
                    val type = cols.getOrNull(typeCol)?.takeIf { it.isNotBlank() && it != "n/a" }
                    if (sig != null || type != null) name = listOfNotNull(sig, type?.let { "($it)" }).joinToString(" ")
                }
                if (hash == null) hash = hexToken.find(line)?.value
                if (hash == null) { invalid++; continue }
                read++
                batch += hash.lowercase() to name
                if (batch.size >= 5000) {
                    added += db.insertSignatures(batch, source); batch.clear(); onProgress(read)
                }
            }
            if (batch.isNotEmpty()) added += db.insertSignatures(batch, source)
            onProgress(read)
        }

        val resolver = context.contentResolver
        val isZip = resolver.openInputStream(uri)?.use { s ->
            val h = ByteArray(4); val n = s.read(h)
            n == 4 && h[0] == 0x50.toByte() && h[1] == 0x4B.toByte() && h[2] == 0x03.toByte() && h[3] == 0x04.toByte()
        } ?: throw java.io.IOException("No se pudo abrir el archivo")

        resolver.openInputStream(uri)?.use { input ->
            if (isZip) {
                ZipInputStream(input).use { z ->
                    while (true) {
                        val e = z.nextEntry ?: break
                        if (e.isDirectory) continue
                        val n = e.name.lowercase()
                        if (n.endsWith(".txt") || n.endsWith(".csv")) {
                            // No cerrar el stream del zip al terminar la entrada
                            consume(object : java.io.FilterInputStream(z) { override fun close() {} })
                        }
                    }
                }
            } else consume(input)
        } ?: throw java.io.IOException("No se pudo abrir el archivo")

        db.log("Firmas importadas", "$fileName: $read hashes leídos, $added nuevos, $invalid líneas inválidas")
        return Result(read, added, invalid, source)
    }

    private fun splitCsv(line: String): List<String> =
        line.split(',').map { it.trim().trim('"').trim() }

    private fun displayName(uri: Uri): String? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()
}
