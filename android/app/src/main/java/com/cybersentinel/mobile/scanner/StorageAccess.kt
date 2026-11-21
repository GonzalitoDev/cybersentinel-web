package com.cybersentinel.mobile.scanner

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.Settings
import androidx.core.content.ContextCompat

/**
 * Centraliza cómo la app obtiene acceso a archivos usando SÓLO mecanismos oficiales:
 *  - Storage Access Framework: el usuario elige carpetas y otorga permiso persistente.
 *  - "Acceso a todos los archivos" (Android 11+) o READ/WRITE_EXTERNAL_STORAGE (Android 8–10),
 *    opcional y activado por el usuario, para el análisis completo del almacenamiento compartido.
 * Nunca se accede a /data, Android/data, Android/obb ni carpetas privadas de otras apps.
 */
object StorageAccess {

    const val EXTERNAL_STORAGE_AUTHORITY = "com.android.externalstorage.documents"

    data class SafFolder(val treeUri: Uri, val displayName: String, val canWrite: Boolean)

    fun hasAllFilesAccess(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        }

    /** Necesario en Android 8–10 para poder mover archivos a cuarentena en modo ruta. */
    fun hasLegacyWrite(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    /** Intent oficial para que el usuario conceda "Acceso a todos los archivos" (Android 11+). */
    fun allFilesAccessIntent(context: Context): Intent? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        val specific = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${context.packageName}"))
        return if (specific.resolveActivity(context.packageManager) != null) specific
        else Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
    }

    fun safFolders(context: Context): List<SafFolder> =
        context.contentResolver.persistedUriPermissions
            .filter { it.isReadPermission && DocumentsContract.isTreeUri(it.uri) }
            .map { SafFolder(it.uri, describeTree(it.uri), it.isWritePermission) }

    fun describeTree(treeUri: Uri): String {
        val docId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull() ?: return treeUri.toString()
        return if (treeUri.authority == EXTERNAL_STORAGE_AUTHORITY) {
            val volume = docId.substringBefore(':')
            val path = docId.substringAfter(':', "")
            val volName = if (volume == "primary") "Almacenamiento interno" else "Tarjeta SD ($volume)"
            if (path.isEmpty()) volName else "$volName/$path"
        } else {
            "${treeUri.authority}: $docId"
        }
    }

    /** true si la carpeta SAF está en el almacenamiento interno (ya cubierto por el modo "todos los archivos"). */
    fun isPrimaryTree(treeUri: Uri): Boolean {
        if (treeUri.authority != EXTERNAL_STORAGE_AUTHORITY) return false
        val docId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull() ?: return false
        return docId.startsWith("primary:")
    }

    fun releaseFolder(context: Context, treeUri: Uri) {
        runCatching {
            context.contentResolver.releasePersistableUriPermission(
                treeUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }.onFailure {
            runCatching { context.contentResolver.releasePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        }
    }

    fun persistFolder(context: Context, treeUri: Uri) {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        runCatching { context.contentResolver.takePersistableUriPermission(treeUri, flags) }
            .onFailure { context.contentResolver.takePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
    }
}
