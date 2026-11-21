package com.cybersentinel.mobile.ui.screens

import android.Manifest
import android.content.ActivityNotFoundException
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.navigation.NavHostController
import com.cybersentinel.mobile.Routes
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.scanner.Hashing
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.scanner.SignatureImporter
import com.cybersentinel.mobile.scanner.StorageAccess
import com.cybersentinel.mobile.ui.components.ConfirmDialog
import com.cybersentinel.mobile.ui.components.CsCard
import com.cybersentinel.mobile.ui.components.CsTopBar
import com.cybersentinel.mobile.ui.components.NavRow
import com.cybersentinel.mobile.ui.components.SectionTitle
import com.cybersentinel.mobile.ui.components.rememberQuery
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.util.Prefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private class SettingsData(
    val allFiles: Boolean,
    val folders: List<StorageAccess.SafFolder>,
    val signatureCount: Long,
    val sources: List<Pair<String, Long>>,
    val trusted: List<String>
)

@Composable
fun SettingsScreen(nav: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val prefs = remember { Prefs(context) }
    var hashMb by remember { mutableFloatStateOf(prefs.maxHashMb.toFloat()) }
    var includeSystem by remember { mutableStateOf(prefs.includeSystemApps) }
    var importing by remember { mutableStateOf<String?>(null) }
    var showHashDialog by remember { mutableStateOf(false) }
    var removeFolder by remember { mutableStateOf<StorageAccess.SafFolder?>(null) }
    var removeSource by remember { mutableStateOf<String?>(null) }

    // Al volver de los Ajustes del sistema, refrescar el estado de permisos.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { ScanManager.notifyDataChanged() }

    val data by rememberQuery {
        val db = Database.get(context)
        SettingsData(
            StorageAccess.hasAllFilesAccess(context),
            StorageAccess.safFolders(context),
            db.signatureCount(),
            db.signatureSources(),
            db.trustedKeys()
        )
    }

    fun toast(msg: String) { scope.launch { snackbar.showSnackbar(msg) } }

    val folderLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            val ok = runCatching { StorageAccess.persistFolder(context, uri) }.isSuccess
            val name = StorageAccess.describeTree(uri)
            if (ok) Database.get(context).log("Carpeta autorizada", name)
            ScanManager.notifyDataChanged()
            withContext(Dispatchers.Main) { snackbar.showSnackbar(if (ok) "Carpeta agregada: $name" else "No se pudo conservar el permiso") }
        }
    }

    val legacyPermLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { res ->
        val granted = res.values.all { it }
        scope.launch(Dispatchers.IO) { Database.get(context).log("Permiso de almacenamiento", if (granted) "concedido" else "denegado") }
        ScanManager.notifyDataChanged()
        toast(if (granted) "Permiso concedido" else "Permiso denegado")
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        importing = "Importando firmas…"
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                try {
                    val r = SignatureImporter(context).import(uri) { n -> importing = "Importando firmas… $n leídas" }
                    if (r.read == 0) "El archivo no contiene hashes SHA-256 válidos."
                    else "${r.read} hashes leídos, ${r.added} nuevos" + if (r.invalidLines > 0) " (${r.invalidLines} líneas ignoradas)" else ""
                } catch (e: Exception) {
                    "No se pudo importar: ${e.message}"
                }
            }
            importing = null
            ScanManager.notifyDataChanged()
            snackbar.showSnackbar(msg)
        }
    }

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }, containerColor = CsColors.Background, contentWindowInsets = WindowInsets(0, 0, 0, 0)) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            CsTopBar("Configuración y permisos")
            val d = data
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {

                // --------------------------------------------------------- archivos
                SectionTitle("Acceso a archivos")
                CsCard {
                    Text("Acceso a todos los archivos", style = MaterialTheme.typography.titleMedium)
                    Text(
                        if (d?.allFiles == true) "ACTIVO" else "No activo",
                        color = if (d?.allFiles == true) CsColors.Green else CsColors.TextDim,
                        style = MaterialTheme.typography.labelSmall
                    )
                    Text(
                        "Opcional. Permite el análisis completo del almacenamiento compartido, incluida la carpeta Descargas " +
                            "(Android no deja autorizar Descargas como carpeta suelta). También es necesario para mover a cuarentena " +
                            "archivos encontrados por esta vía. Nunca da acceso a datos privados de otras apps ni a archivos del sistema.",
                        style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(vertical = 6.dp)
                    )
                    OutlinedButton(onClick = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            val intent = StorageAccess.allFilesAccessIntent(context)
                            try { if (intent != null) context.startActivity(intent) } catch (e: ActivityNotFoundException) { toast("No se encontró la pantalla de ajustes") }
                        } else {
                            legacyPermLauncher.launch(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE))
                        }
                    }) { Text(if (d?.allFiles == true) "Revisar en Ajustes del sistema" else "Conceder acceso") }
                }
                Spacer(Modifier.height(10.dp))
                CsCard {
                    Text("Carpetas autorizadas (Storage Access Framework)", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Sin permisos amplios: elegís carpetas puntuales (por ejemplo Documentos, WhatsApp/Media, una subcarpeta de Descargas o la tarjeta SD).",
                        style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(vertical = 6.dp)
                    )
                    d?.folders?.forEach { f ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(f.displayName, style = MaterialTheme.typography.bodyMedium)
                                Text(if (f.canWrite) "lectura y escritura" else "sólo lectura", style = MaterialTheme.typography.labelSmall, color = CsColors.TextDim)
                            }
                            TextButton(onClick = { removeFolder = f }) { Text("Quitar", color = CsColors.Critical) }
                        }
                    }
                    if (d?.folders?.isEmpty() == true) Text("Ninguna carpeta autorizada.", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                    OutlinedButton(onClick = { folderLauncher.launch(null) }, modifier = Modifier.padding(top = 6.dp)) { Text("Agregar carpeta") }
                }

                // ----------------------------------------------------------- firmas
                SectionTitle("Base de firmas (SHA-256)")
                CsCard {
                    Text("${d?.signatureCount ?: "…"} firmas en la base local", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Un archivo o APK se marca como CRÍTICO sólo si su SHA-256 coincide exactamente con una de estas firmas. " +
                            "La app trae únicamente la firma de prueba EICAR. Para detectar malware real importá una lista de hashes: " +
                            "por ejemplo, descargá desde tu navegador la exportación de SHA-256 de MalwareBazaar (abuse.ch) en .txt, .csv o .zip y elegila acá. " +
                            "La importación es local; la app no se conecta a Internet.",
                        style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(vertical = 6.dp)
                    )
                    d?.sources?.forEach { (src, n) ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("$src: $n", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                            if (src != "Incluida") TextButton(onClick = { removeSource = src }) { Text("Quitar", color = CsColors.Critical) }
                        }
                    }
                    importing?.let { Text(it, color = CsColors.Blue, style = MaterialTheme.typography.bodySmall) }
                    Row {
                        Button(
                            onClick = { importLauncher.launch(arrayOf("*/*")) }, enabled = importing == null,
                            colors = ButtonDefaults.buttonColors(containerColor = CsColors.Blue)
                        ) { Text("Importar archivo") }
                        Spacer(Modifier.padding(4.dp))
                        OutlinedButton(onClick = { showHashDialog = true }) { Text("Agregar hash") }
                    }
                }

                // ---------------------------------------------------------- análisis
                SectionTitle("Análisis")
                CsCard {
                    Text("Calcular SHA-256 hasta ${hashMb.toInt()} MB por archivo", style = MaterialTheme.typography.bodyMedium)
                    Slider(
                        value = hashMb, onValueChange = { hashMb = it }, valueRange = 10f..500f,
                        onValueChangeFinished = { prefs.maxHashMb = hashMb.toInt() }
                    )
                    Text(
                        "Los archivos más grandes se analizan por tipo, nombre y ubicación, pero sin hash (se indica en el informe).",
                        style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Incluir apps del sistema", style = MaterialTheme.typography.bodyMedium)
                            Text("Las lista en el análisis de apps (sus APK no se hashean).", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                        }
                        Switch(
                            checked = includeSystem, onCheckedChange = { includeSystem = it; prefs.includeSystemApps = it },
                            colors = SwitchDefaults.colors(checkedTrackColor = CsColors.Green)
                        )
                    }
                }

                // --------------------------------------------------------- confiables
                if (!d?.trusted.isNullOrEmpty()) {
                    SectionTitle("Elementos marcados como confiables")
                    CsCard {
                        d?.trusted?.forEach { key ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(key, style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(1f))
                                TextButton(onClick = {
                                    scope.launch(Dispatchers.IO) {
                                        val db = Database.get(context)
                                        db.setTrusted(key, false)
                                        db.log("Quitado de confiables", key)
                                        ScanManager.notifyDataChanged()
                                    }
                                }) { Text("Quitar") }
                            }
                        }
                    }
                }

                SectionTitle("Herramientas")
                NavRow(Icons.Filled.Lock, "Cuarentena", "Restaurar o eliminar archivos aislados") { nav.navigate(Routes.QUARANTINE) }
                NavRow(Icons.AutoMirrored.Filled.List, "Registro de acciones", "Todo lo que hizo la app, con fecha y hora") { nav.navigate(Routes.LOG) }

                // --------------------------------------------------------- permisos
                SectionTitle("Para qué se usa cada permiso")
                PermissionExplanation("Ver todas las apps (QUERY_ALL_PACKAGES)", "Para listar las aplicaciones instaladas y revisar sus permisos y origen. Sin él, Android oculta la mayoría de las apps.")
                PermissionExplanation("Acceso a todos los archivos (MANAGE_EXTERNAL_STORAGE) — opcional", "Para el análisis completo del almacenamiento compartido y la cuarentena de esos archivos. Lo activás vos desde Ajustes.")
                PermissionExplanation("Almacenamiento (READ/WRITE_EXTERNAL_STORAGE) — sólo Android 8 a 10", "Equivalente al anterior en versiones viejas de Android.")
                PermissionExplanation("Solicitar desinstalación (REQUEST_DELETE_PACKAGES)", "Para abrir el diálogo oficial de desinstalación cuando vos lo pedís. Android siempre te pide confirmar.")
                PermissionExplanation("Sin permiso de Internet", "La app no declara INTERNET: es imposible que envíe archivos o datos fuera del teléfono.")

                SectionTitle("Privacidad")
                Text(
                    "Todo el análisis ocurre en el teléfono. Los resultados, el historial y la cuarentena se guardan en el almacenamiento privado " +
                        "de la app y están excluidos de las copias de seguridad en la nube. No hay cuentas, publicidad ni estadísticas.",
                    style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim
                )
                Spacer(Modifier.height(30.dp))
            }
        }
    }

    removeFolder?.let { f ->
        ConfirmDialog(
            title = "¿Quitar ${f.displayName}?",
            message = "La app dejará de tener acceso a esa carpeta. Los archivos no se modifican.",
            confirmText = "Quitar", destructive = true,
            onConfirm = {
                scope.launch(Dispatchers.IO) {
                    StorageAccess.releaseFolder(context, f.treeUri)
                    Database.get(context).log("Carpeta quitada", f.displayName)
                    ScanManager.notifyDataChanged()
                }
            },
            onDismiss = { removeFolder = null }
        )
    }

    removeSource?.let { src ->
        ConfirmDialog(
            title = "¿Quitar firmas?",
            message = "Se eliminarán de la base local todas las firmas de \"$src\".",
            confirmText = "Quitar", destructive = true,
            onConfirm = {
                scope.launch(Dispatchers.IO) {
                    val db = Database.get(context)
                    val n = db.deleteSignatureSource(src)
                    db.log("Firmas eliminadas", "$src: $n")
                    ScanManager.notifyDataChanged()
                }
            },
            onDismiss = { removeSource = null }
        )
    }

    if (showHashDialog) {
        var hash by remember { mutableStateOf("") }
        var name by remember { mutableStateOf("") }
        val valid = Hashing.isSha256(hash.trim())
        AlertDialog(
            onDismissRequest = { showHashDialog = false },
            title = { Text("Agregar firma manual") },
            text = {
                Column {
                    OutlinedTextField(value = hash, onValueChange = { hash = it }, label = { Text("SHA-256 (64 caracteres hex)") }, singleLine = true, isError = hash.isNotBlank() && !valid)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Nombre de la amenaza") }, singleLine = true)
                }
            },
            confirmButton = {
                TextButton(enabled = valid, onClick = {
                    showHashDialog = false
                    val h = hash.trim().lowercase()
                    val n = name.trim().ifEmpty { "Firma agregada manualmente" }
                    scope.launch {
                        val added = withContext(Dispatchers.IO) {
                            val db = Database.get(context)
                            db.insertSignatures(listOf(h to n), "Manual").also { db.log("Firma agregada", "$h — $n") }
                        }
                        ScanManager.notifyDataChanged()
                        snackbar.showSnackbar(if (added > 0) "Firma agregada" else "Esa firma ya estaba en la base")
                    }
                }) { Text("Agregar", fontWeight = FontWeight.Bold) }
            },
            dismissButton = { TextButton(onClick = { showHashDialog = false }) { Text("Cancelar") } },
            containerColor = CsColors.SurfaceHigh
        )
    }
}

@Composable
private fun PermissionExplanation(title: String, text: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
        Text(title, style = MaterialTheme.typography.bodyMedium, color = CsColors.Text)
        Text(text, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
    }
}
