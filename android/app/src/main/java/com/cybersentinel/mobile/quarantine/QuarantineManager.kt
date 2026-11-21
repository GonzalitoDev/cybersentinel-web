package com.cybersentinel.mobile.quarantine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.FindingStatus
import com.cybersentinel.mobile.data.QuarantineItem
import com.cybersentinel.mobile.scanner.Hashing
import com.cybersentinel.mobile.scanner.Hashing.toHex
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID

/**
 * Cuarentena segura:
 *  - Nunca actúa sin confirmación (la UI siempre pide confirmar).
 *  - Copia el archivo al almacenamiento PRIVADO de la app, ofuscado (no se puede abrir ni ejecutar por accidente),
 *    verifica el SHA-256 de la copia y recién entonces borra el original.
 *  - Si algo falla, deshace la copia y deja el original intacto.
 *  - Permite restaurar al lugar original (verificando el hash) o eliminar definitivamente.
 *  - Rechaza rutas del sistema.
 */
class QuarantineManager(private val context: Context) {

    private val db = Database.get(context)
    private val dir = File(context.filesDir, "quarantine").apply { mkdirs() }

    private val forbiddenPrefixes = listOf("/system", "/vendor", "/product", "/apex", "/data", "/proc", "/sys", "/odm", "/oem", "/dev")

    class QuarantineException(message: String) : Exception(message)

    fun quarantine(f: Finding): QuarantineItem {
        if (f.kind != FindingKind.FILE) throw QuarantineException("Sólo se pueden poner archivos en cuarentena. Para apps, usá Desinstalar.")
        if (f.isDirectory) throw QuarantineException("Las carpetas no se ponen en cuarentena; revisá los archivos que contiene.")
        val uri = f.uri ?: throw QuarantineException("No se conoce la ubicación del archivo.")
        val kind = f.storageKind ?: throw QuarantineException("Tipo de almacenamiento desconocido.")
        if (kind == "FILE") {
            val canonical = File(uri).canonicalPath
            if (forbiddenPrefixes.any { canonical == it || canonical.startsWith("$it/") }) {
                throw QuarantineException("Por seguridad no se modifican archivos del sistema.")
            }
        }

        val stored = File(dir, UUID.randomUUID().toString() + ".qbin")
        val (sha, size) = try {
            openSource(kind, uri).use { input -> stored.outputStream().use { out -> encode(input, out) } }
        } catch (e: Exception) {
            stored.delete()
            throw QuarantineException("No se pudo leer el archivo: ${e.message ?: e.javaClass.simpleName}")
        }
        // Verificación de la copia antes de borrar el original
        val verify = stored.inputStream().use { input -> hashEncoded(input) }
        if (verify != sha) {
            stored.delete()
            throw QuarantineException("La copia de cuarentena no coincide con el original. No se modificó nada.")
        }

        val deleted = runCatching { deleteSource(kind, uri) }.getOrDefault(false)
        if (!deleted) {
            stored.delete()
            throw QuarantineException(
                "No se pudo quitar el archivo de su ubicación (falta permiso de escritura). " +
                    "No se modificó nada. Si es una carpeta agregada, volvé a agregarla para conceder escritura."
            )
        }

        val parent = when (kind) {
            "FILE" -> File(uri).parent ?: ""
            else -> f.parentUri ?: parentDocumentUri(uri) ?: ""
        }
        val item = QuarantineItem(
            originalName = f.name,
            originalLocation = f.location,
            originalUri = uri,
            parentUri = parent,
            storageKind = kind,
            mime = null,
            sha256 = sha,
            size = size,
            quarantinedAt = System.currentTimeMillis(),
            storedFile = stored.name,
            reason = "${f.level.label}: ${f.title}",
            findingId = f.id.takeIf { it > 0 }
        )
        val id = db.insertQuarantine(item)
        if (f.id > 0) db.updateFindingStatus(f.id, FindingStatus.QUARANTINED)
        db.log("Cuarentena", "${f.name} (${f.location}) — SHA-256 $sha — motivo: ${item.reason}")
        return item.copy(id = id)
    }

    /** Restaura al lugar original. Si ya existe un archivo con ese nombre, se agrega " (restaurado)". */
    fun restore(item: QuarantineItem): String {
        val stored = File(dir, item.storedFile)
        if (!stored.exists()) throw QuarantineException("No se encontró la copia en cuarentena.")
        val restoredName: String
        when (item.storageKind) {
            "FILE" -> {
                val parent = File(item.parentUri)
                if (!parent.exists() && !parent.mkdirs()) throw QuarantineException("No se puede crear la carpeta original. Usá \"Restaurar en…\".")
                var target = File(parent, item.originalName)
                if (target.exists()) target = File(parent, withSuffix(item.originalName))
                try {
                    stored.inputStream().use { input -> target.outputStream().use { out -> decode(input, out) } }
                } catch (e: Exception) {
                    target.delete()
                    throw QuarantineException("No se pudo escribir en la ubicación original (${e.message}). Usá \"Restaurar en…\".")
                }
                val check = target.inputStream().use { sha256Plain(it) }
                if (check != item.sha256) { target.delete(); throw QuarantineException("Verificación fallida al restaurar. El archivo sigue en cuarentena.") }
                restoredName = target.absolutePath
            }
            else -> {
                val parentUri = Uri.parse(item.parentUri)
                val created = runCatching {
                    DocumentsContract.createDocument(context.contentResolver, parentUri, "application/octet-stream", item.originalName)
                }.getOrNull() ?: throw QuarantineException("No hay permiso para escribir en la carpeta original. Usá \"Restaurar en…\".")
                writeTo(stored, created, item.sha256)
                restoredName = "${item.originalLocation}/${item.originalName}"
            }
        }
        finish(item, FindingStatus.RESTORED)
        db.log("Restaurado", "${item.originalName} → $restoredName")
        return restoredName
    }

    /** Restaura en un archivo nuevo elegido por el usuario con el selector del sistema. */
    fun restoreTo(item: QuarantineItem, target: Uri) {
        val stored = File(dir, item.storedFile)
        if (!stored.exists()) throw QuarantineException("No se encontró la copia en cuarentena.")
        writeTo(stored, target, item.sha256)
        finish(item, FindingStatus.RESTORED)
        db.log("Restaurado en otra ubicación", "${item.originalName} → $target")
    }

    fun deletePermanently(item: QuarantineItem) {
        val stored = File(dir, item.storedFile)
        if (stored.exists() && !stored.delete()) throw QuarantineException("No se pudo eliminar la copia en cuarentena.")
        db.deleteQuarantine(item.id)
        item.findingId?.let { db.updateFindingStatus(it, FindingStatus.DELETED) }
        db.log("Eliminado definitivamente", "${item.originalName} — SHA-256 ${item.sha256}")
    }

    // ----------------------------------------------------------------------------- helpers

    private fun finish(item: QuarantineItem, status: FindingStatus) {
        File(dir, item.storedFile).delete()
        db.deleteQuarantine(item.id)
        item.findingId?.let { db.updateFindingStatus(it, status) }
    }

    private fun writeTo(stored: File, target: Uri, expectedSha: String) {
        try {
            val out = context.contentResolver.openOutputStream(target, "w") ?: throw IOException("sin salida")
            out.use { o -> stored.inputStream().use { input -> decode(input, o) } }
            val check = context.contentResolver.openInputStream(target)?.use { sha256Plain(it) }
            if (check != null && check != expectedSha) throw IOException("el hash no coincide")
        } catch (e: Exception) {
            runCatching { DocumentsContract.deleteDocument(context.contentResolver, target) }
            throw QuarantineException("No se pudo restaurar: ${e.message}. El archivo sigue en cuarentena.")
        }
    }

    private fun openSource(kind: String, uri: String): InputStream = when (kind) {
        "FILE" -> File(uri).inputStream()
        else -> context.contentResolver.openInputStream(Uri.parse(uri)) ?: throw IOException("no se pudo abrir")
    }

    private fun deleteSource(kind: String, uri: String): Boolean = when (kind) {
        "FILE" -> File(uri).delete()
        else -> DocumentsContract.deleteDocument(context.contentResolver, Uri.parse(uri))
    }

    /** URI del documento padre, reconstruida a partir del ID de documento (proveedor de almacenamiento externo). */
    private fun parentDocumentUri(docUriString: String): String? = runCatching {
        val docUri = Uri.parse(docUriString)
        val docId = DocumentsContract.getDocumentId(docUri)
        val treeId = DocumentsContract.getTreeDocumentId(docUri)
        val parentId = docId.substringBeforeLast('/', missingDelimiterValue = "")
        val pid = if (parentId.isEmpty() || parentId.length < treeId.length) treeId else parentId
        val tree = DocumentsContract.buildTreeDocumentUri(docUri.authority!!, treeId)
        DocumentsContract.buildDocumentUriUsingTree(tree, pid).toString()
    }.getOrNull()

    private fun withSuffix(name: String): String {
        val dot = name.lastIndexOf('.')
        return if (dot > 0) name.substring(0, dot) + " (restaurado)" + name.substring(dot) else "$name (restaurado)"
    }

    private val key = "CyberSentinel-Quarantine".toByteArray()

    private fun xorInPlace(buf: ByteArray, n: Int, offset: Long) {
        for (i in 0 until n) buf[i] = (buf[i].toInt() xor key[((offset + i) % key.size).toInt()].toInt()).toByte()
    }

    /** Original -> cuarentena. Devuelve (SHA-256 del contenido original, tamaño). */
    private fun encode(input: InputStream, out: OutputStream): Pair<String, Long> {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(64 * 1024)
        var pos = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
            xorInPlace(buf, n, pos)
            out.write(buf, 0, n)
            pos += n
        }
        return md.digest().toHex() to pos
    }

    /** Cuarentena -> original. Devuelve el SHA-256 del contenido restaurado. */
    private fun decode(input: InputStream, out: OutputStream?): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(64 * 1024)
        var pos = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            xorInPlace(buf, n, pos)
            md.update(buf, 0, n)
            out?.write(buf, 0, n)
            pos += n
        }
        return md.digest().toHex()
    }

    private fun hashEncoded(input: InputStream): String = decode(input, null)

    private fun sha256Plain(input: InputStream): String = Hashing.sha256(input)
}
