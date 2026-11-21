package com.cybersentinel.mobile.ui.screens

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.FindingStatus
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.quarantine.QuarantineManager
import com.cybersentinel.mobile.scanner.PermissionCatalog
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.ui.components.ConfirmDialog
import com.cybersentinel.mobile.ui.components.CsCard
import com.cybersentinel.mobile.ui.components.CsTopBar
import com.cybersentinel.mobile.ui.components.EmptyState
import com.cybersentinel.mobile.ui.components.KeyValue
import com.cybersentinel.mobile.ui.components.LevelBadge
import com.cybersentinel.mobile.ui.components.SectionTitle
import com.cybersentinel.mobile.ui.components.rememberQuery
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.ui.theme.color
import com.cybersentinel.mobile.util.Format
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class PermRow(val name: String, val label: String, val description: String?, val sensitive: Boolean, val granted: Boolean)

private class DetailData(val finding: Finding?, val installed: Boolean, val permissions: List<PermRow>, val trusted: Boolean)

@Suppress("DEPRECATION")
private fun loadPermissions(context: Context, pkg: String): Pair<Boolean, List<PermRow>> {
    val pm = context.packageManager
    val info: PackageInfo = runCatching {
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        else pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
    }.getOrNull() ?: return false to emptyList()
    val req = info.requestedPermissions ?: return true to emptyList()
    val flags = info.requestedPermissionsFlags
    val rows = req.mapIndexed { i, p ->
        val granted = flags != null && i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        val meta = PermissionCatalog.map[p]
        PermRow(p, meta?.label ?: p.substringAfterLast('.'), meta?.description, meta?.sensitive == true, granted)
    }.sortedWith(compareByDescending<PermRow> { it.sensitive }.thenByDescending { it.granted }.thenBy { it.label })
    return true to rows
}

@Composable
fun FindingDetailScreen(nav: NavHostController, id: Long) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current
    var confirm by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val data by rememberQuery(id) {
        val db = Database.get(context)
        val f = db.getFinding(id)
        var installed = false
        var perms = emptyList<PermRow>()
        var trusted = false
        if (f != null) {
            if (f.kind == FindingKind.APP && f.packageName != null) {
                val r = loadPermissions(context, f.packageName)
                installed = r.first; perms = r.second
                trusted = db.isTrusted("app:${f.packageName}")
            } else if (f.sha256 != null) {
                trusted = db.isTrusted("hash:${f.sha256}")
            }
        }
        DetailData(f, installed, perms, trusted)
    }

    val uninstallLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val f = data?.finding ?: return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            val stillInstalled = f.packageName?.let { loadPermissions(context, it).first } ?: true
            val db = Database.get(context)
            if (!stillInstalled) {
                db.updateFindingStatus(f.id, FindingStatus.UNINSTALLED)
                db.log("Desinstalación", "${f.name} (${f.packageName}) fue desinstalada")
            } else {
                db.log("Desinstalación", "Se abrió el diálogo para ${f.packageName}; la app sigue instalada")
            }
            ScanManager.notifyDataChanged()
            withContext(Dispatchers.Main) { snackbar.showSnackbar(if (!stillInstalled) "App desinstalada" else "La app sigue instalada") }
        }
    }

    fun openIntent(intent: Intent) {
        try { context.startActivity(intent) } catch (e: ActivityNotFoundException) {
            scope.launch { snackbar.showSnackbar("Este teléfono no tiene esa pantalla de ajustes") }
        }
    }

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }, containerColor = CsColors.Background, contentWindowInsets = WindowInsets(0, 0, 0, 0)) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            CsTopBar("Detalle", onBack = { nav.popBackStack() })
            val d = data ?: return@Column
            val f = d.finding
            if (f == null) { EmptyState("No encontrado", "Este elemento ya no existe en el historial."); return@Column }

            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
                CsCard(accent = f.level.color()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(f.name, style = MaterialTheme.typography.titleLarge)
                            Text(f.title, style = MaterialTheme.typography.bodyMedium, color = f.level.color())
                        }
                        LevelBadge(f.level)
                    }
                    if (f.status != FindingStatus.OPEN) {
                        Text("Estado: ${f.status.label}", style = MaterialTheme.typography.bodySmall, color = CsColors.Blue, modifier = Modifier.padding(top = 6.dp))
                    }
                }

                // ----------------------------------------------------------- motivos
                val levelReasons = f.reasons.filter { it.startsWith("[") }
                val infoLines = f.reasons.filterNot { it.startsWith("[") }
                if (levelReasons.isNotEmpty()) {
                    SectionTitle("Por qué tiene este nivel")
                    levelReasons.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(vertical = 3.dp)) }
                }
                if (infoLines.isNotEmpty()) {
                    SectionTitle("Información")
                    infoLines.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(vertical = 2.dp)) }
                }

                // ------------------------------------------------------------- datos
                SectionTitle("Datos")
                when (f.kind) {
                    FindingKind.APP -> {
                        KeyValue("Paquete", f.packageName ?: "—", mono = true)
                        KeyValue("Origen de instalación", f.location)
                        KeyValue("Instalada", Format.dateTime(f.createdAt))
                        KeyValue("Última actualización", Format.dateTime(f.modifiedAt))
                        KeyValue("Tamaño del APK", Format.size(f.size))
                        KeyValue("Estado actual", if (d.installed) "Instalada" else "No instalada")
                    }
                    FindingKind.FILE -> {
                        KeyValue("Ubicación", f.location)
                        if (!f.isDirectory) {
                            KeyValue("Tamaño", Format.size(f.size))
                            KeyValue("Tipo real (por contenido)", f.realType ?: "no determinado")
                        }
                        KeyValue("Creación", Format.dateTime(f.createdAt))
                        KeyValue("Modificación", Format.dateTime(f.modifiedAt))
                        KeyValue("Oculto", if (f.isHidden) "Sí" else "No")
                    }
                    FindingKind.DEVICE -> KeyValue("Ámbito", f.location)
                }
                f.sha256?.let { sha ->
                    KeyValue("SHA-256", sha, mono = true)
                    TextButton(onClick = {
                        clipboard.setText(AnnotatedString(sha))
                        scope.launch { snackbar.showSnackbar("SHA-256 copiado") }
                    }) { Text("Copiar SHA-256") }
                }

                // ---------------------------------------------------------- acciones
                SectionTitle("Acciones")
                if (f.kind == FindingKind.FILE && !f.isDirectory && (f.status == FindingStatus.OPEN || f.status == FindingStatus.IGNORED)) {
                    Button(
                        onClick = { confirm = "quarantine" }, enabled = !busy, modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CsColors.Critical)
                    ) { Text("Poner en cuarentena", fontWeight = FontWeight.Bold) }
                    Spacer(Modifier.height(8.dp))
                }
                if (f.kind == FindingKind.APP && d.installed && f.packageName != null) {
                    Button(onClick = { confirm = "uninstall" }, modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CsColors.Critical)) { Text("Desinstalar…", fontWeight = FontWeight.Bold) }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = {
                        openIntent(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${f.packageName}")))
                    }, modifier = Modifier.fillMaxWidth()) { Text("Ver permisos en Ajustes del sistema") }
                    if (f.reasons.any { it.contains("accesibilidad", true) }) {
                        OutlinedButton(onClick = { openIntent(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }, modifier = Modifier.fillMaxWidth()) {
                            Text("Ajustes de accesibilidad")
                        }
                    }
                    if (f.reasons.any { it.contains("administra", true) }) {
                        OutlinedButton(onClick = { openIntent(Intent(Settings.ACTION_SECURITY_SETTINGS)) }, modifier = Modifier.fillMaxWidth()) {
                            Text("Ajustes de seguridad (administradores del dispositivo)")
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                }
                val canTrust = f.level != RiskLevel.CRITICAL && f.kind != FindingKind.DEVICE &&
                    ((f.kind == FindingKind.APP && f.packageName != null) || f.sha256 != null) &&
                    f.status != FindingStatus.QUARANTINED && f.status != FindingStatus.DELETED
                if (canTrust) {
                    OutlinedButton(onClick = { confirm = if (d.trusted) "untrust" else "trust" }, modifier = Modifier.fillMaxWidth()) {
                        Text(if (d.trusted) "Quitar de confiables" else "Marcar como confiable", color = CsColors.Blue)
                    }
                }
                if (f.kind == FindingKind.DEVICE) {
                    OutlinedButton(onClick = { openIntent(Intent(Settings.ACTION_SECURITY_SETTINGS)) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Abrir ajustes de seguridad")
                    }
                }

                // -------------------------------------------------------- permisos
                if (f.kind == FindingKind.APP && d.permissions.isNotEmpty()) {
                    SectionTitle("Permisos (${d.permissions.size}) — consulta en vivo")
                    d.permissions.forEach { p ->
                        Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                Text(p.label, style = MaterialTheme.typography.bodyMedium, color = if (p.sensitive) CsColors.Medium else CsColors.Text, modifier = Modifier.weight(1f))
                                Text(if (p.granted) "concedido" else "solicitado", style = MaterialTheme.typography.labelSmall,
                                    color = if (p.granted) CsColors.Green else CsColors.TextDim)
                            }
                            p.description?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim) }
                            Text(p.name, style = MaterialTheme.typography.labelSmall, color = CsColors.Outline)
                        }
                    }
                }
                Spacer(Modifier.height(30.dp))
            }

            // ---------------------------------------------------------- diálogos
            when (confirm) {
                "quarantine" -> ConfirmDialog(
                    title = "¿Poner en cuarentena?",
                    message = "\"${f.name}\" se moverá a un área aislada dentro de la app y dejará de estar en ${f.location}. " +
                        "Se verifica con SHA-256 antes de quitar el original. Podés restaurarlo cuando quieras.",
                    confirmText = "Mover a cuarentena", destructive = true,
                    onConfirm = {
                        busy = true
                        scope.launch {
                            val msg = withContext(Dispatchers.IO) {
                                try { QuarantineManager(context).quarantine(f); "Archivo movido a cuarentena" }
                                catch (e: QuarantineManager.QuarantineException) { e.message ?: "No se pudo" }
                                catch (e: Exception) { "Error: ${e.message}" }
                            }
                            busy = false
                            ScanManager.notifyDataChanged()
                            snackbar.showSnackbar(msg)
                        }
                    },
                    onDismiss = { confirm = null }
                )
                "uninstall" -> ConfirmDialog(
                    title = "¿Desinstalar ${f.name}?",
                    message = "Se abrirá el diálogo oficial de Android para que confirmes. Si la app es administradora del dispositivo, primero quitale ese permiso.",
                    confirmText = "Continuar", destructive = true,
                    onConfirm = {
                        scope.launch(Dispatchers.IO) { Database.get(context).log("Desinstalación solicitada", "${f.name} (${f.packageName})") }
                        try {
                            uninstallLauncher.launch(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.packageName}")))
                        } catch (e: ActivityNotFoundException) {
                            scope.launch { snackbar.showSnackbar("No se pudo abrir el desinstalador") }
                        }
                    },
                    onDismiss = { confirm = null }
                )
                "trust", "untrust" -> {
                    val trust = confirm == "trust"
                    ConfirmDialog(
                        title = if (trust) "¿Marcar como confiable?" else "¿Quitar de confiables?",
                        message = if (trust) "No contará para el nivel de riesgo en próximos análisis (salvo que coincida con malware conocido). Hacelo sólo si sabés qué es."
                        else "Volverá a evaluarse normalmente en los próximos análisis.",
                        confirmText = if (trust) "Marcar" else "Quitar",
                        onConfirm = {
                            scope.launch(Dispatchers.IO) {
                                val db = Database.get(context)
                                val key = if (f.kind == FindingKind.APP) "app:${f.packageName}" else "hash:${f.sha256}"
                                db.setTrusted(key, trust)
                                db.updateFindingStatus(f.id, if (trust) FindingStatus.IGNORED else FindingStatus.OPEN)
                                db.log(if (trust) "Marcado como confiable" else "Quitado de confiables", "${f.name} ($key)")
                                ScanManager.notifyDataChanged()
                            }
                        },
                        onDismiss = { confirm = null }
                    )
                }
            }
        }
    }
}
