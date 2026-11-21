package com.cybersentinel.mobile.scanner

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.BasicFileAttributes

/**
 * Elemento del almacenamiento (archivo o carpeta), accedido por ruta (modo FILE)
 * o mediante Storage Access Framework (modo SAF).
 */
sealed class ScanNode {
    abstract val name: String
    abstract val displayPath: String
    abstract val isDirectory: Boolean
    abstract val size: Long
    abstract val lastModified: Long?
    abstract val mime: String?
    /** Ruta absoluta o URI de documento. */
    abstract val id: String
    /** Ruta de la carpeta padre o URI de documento de la carpeta padre. */
    abstract val parentId: String
    abstract val storageKind: String
    abstract fun createdAt(): Long?
    abstract fun open(context: Context): InputStream
    abstract fun children(context: Context): List<ScanNode>

    val isHiddenName: Boolean get() = name.startsWith(".")

    class FileNode(val file: File, override val displayPath: String) : ScanNode() {
        override val name: String = file.name
        override val isDirectory: Boolean = file.isDirectory
        override val size: Long = if (isDirectory) 0 else file.length()
        override val lastModified: Long? = file.lastModified().takeIf { it > 0 }
        override val mime: String? = null
        override val id: String = file.absolutePath
        override val parentId: String = file.parentFile?.absolutePath ?: ""
        override val storageKind = "FILE"

        override fun createdAt(): Long? = runCatching {
            val attrs = Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            val created = attrs.creationTime().toMillis()
            // Muchos sistemas de archivos de Android no guardan la fecha de creación y devuelven
            // la de modificación o 0: en ese caso se informa "no disponible" en lugar de inventarla.
            created.takeIf { it > 0 && it != attrs.lastModifiedTime().toMillis() }
        }.getOrNull()

        override fun open(context: Context): InputStream = file.inputStream()

        override fun children(context: Context): List<ScanNode> {
            val list = file.listFiles() ?: return emptyList()
            return list.filter { !Files.isSymbolicLink(it.toPath()) }
                .map { FileNode(it, "$displayPath/${it.name}") }
        }
    }

    class SafNode(
        val treeUri: Uri,
        val documentId: String,
        override val name: String,
        override val mime: String?,
        override val size: Long,
        override val lastModified: Long?,
        private val parentDocumentId: String?,
        override val displayPath: String
    ) : ScanNode() {
        override val isDirectory: Boolean = mime == DocumentsContract.Document.MIME_TYPE_DIR
        val documentUri: Uri get() = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
        override val id: String get() = documentUri.toString()
        override val parentId: String
            get() = parentDocumentId?.let { DocumentsContract.buildDocumentUriUsingTree(treeUri, it).toString() } ?: ""
        override val storageKind = "SAF"

        override fun createdAt(): Long? = null // SAF no expone fecha de creación.

        override fun open(context: Context): InputStream =
            context.contentResolver.openInputStream(documentUri)
                ?: throw java.io.IOException("No se pudo abrir $displayPath")

        override fun children(context: Context): List<ScanNode> {
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId)
            val projection = arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED
            )
            val out = ArrayList<ScanNode>()
            context.contentResolver.query(childrenUri, projection, null, null, null)?.use { c ->
                while (c.moveToNext()) {
                    val docId = c.getString(0) ?: continue
                    val childName = c.getString(1) ?: docId.substringAfterLast('/')
                    out.add(
                        SafNode(
                            treeUri = treeUri,
                            documentId = docId,
                            name = childName,
                            mime = c.getString(2),
                            size = if (c.isNull(3)) 0L else c.getLong(3),
                            lastModified = if (c.isNull(4)) null else c.getLong(4).takeIf { it > 0 },
                            parentDocumentId = documentId,
                            displayPath = "$displayPath/$childName"
                        )
                    )
                }
            }
            return out
        }

        companion object {
            fun root(context: Context, treeUri: Uri): SafNode? {
                val docId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull() ?: return null
                val uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                val projection = arrayOf(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE
                )
                return runCatching {
                    context.contentResolver.query(uri, projection, null, null, null)?.use { c ->
                        if (!c.moveToFirst()) null
                        else SafNode(
                            treeUri, docId, c.getString(0) ?: docId,
                            c.getString(1) ?: DocumentsContract.Document.MIME_TYPE_DIR,
                            0, null, null, StorageAccess.describeTree(treeUri)
                        )
                    }
                }.getOrNull()
            }
        }
    }
}
