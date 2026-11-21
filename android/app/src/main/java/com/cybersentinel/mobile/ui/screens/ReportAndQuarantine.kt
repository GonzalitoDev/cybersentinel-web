package com.cybersentinel.mobile.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybersentinel.mobile.Routes
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.QuarantineItem
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.ScanRecord
import com.cybersentinel.mobile.quarantine.QuarantineManager
import com.cybersentinel.mobile.report.PdfReport
import com.cybersentinel.mobile.report.Recommendations
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.scanner.StorageAccess
import com.cybersentinel.mobile.ui.components.ConfirmDialog
import com.cybersentinel.mobile.ui.components.CsCard
import com.cybersentinel.mobile.ui.components.CsTopBar
import com.cybersentinel.mobile.ui.components.EmptyState
import com.cybersentinel.mobile.ui.components.FindingRow
import com.cybersentinel.mobile.ui.components.LevelBadge
import com.cybersentinel.mobile.ui.components.SectionTitle
import com.cybersentinel.mobile.ui.components.StatTile
import com.cybersentinel.mobile.ui.components.rememberQuery
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.ui.theme.color
import com.cybersentinel.mobile.util.Format
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ============================================================================ INFORME

private class ReportData(val scan: ScanRecord?, val findings: List<Finding>, val recommendations: List<String>)

@Composable
fun ReportScreen(nav: NavHostController, scanId: Long) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var exporting by remember { mutableStateOf(false) }

    val data by rememberQuery(scanId) {
        val db = Database.get(context)
        val scan = db.getScan(scanId)
        val findings = scan?.let { db.getFindings(it.id) } ?: emptyList()
        val access = StorageAccess.hasAllFilesAccess(context) || StorageAccess.safFolders(context).isNotEmpty()
        ReportData(scan, findings, scan?.let { Recommendations.build(it, findings, db.signatureCount(), access) } ?: emptyList())
    }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        exporting = true
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                try {
                    context.contentResolver.openOutputStream(uri)?.use { PdfReport(context).write(scanId, it) }
                        ?: throw java.io.IOException("no se pudo crear el archivo")
                    "Informe PDF guardado"
                } catch (e: Exception) {
                    "No se pudo exportar: ${e.message}"
                }
            }
            exporting = false
            ScanManager.notifyDataChanged()
            snackbar.showSnackbar(msg)
        }
    }

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }, containerColor = CsColors.Background, contentWindowInsets = WindowInsets(0, 0, 0, 0)) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            CsTopBar("Informe #$scanId", onBack = { nav.popBackStack() })
            val d = data ?: return@Column
            val s = d.scan
            if (s == null) { EmptyState("Informe no disponible", "El análisis fue borrado del historial."); return@Column }
            val current = Recommendations.currentLevel(d.findings)
            val confirmed = d.findings.filter { it.level == RiskLevel.CRITICAL }
            val suspicious = d.findings.filter { it.level.weight in 1..3 && it.kind != FindingKind.DEVICE }
            val device = d.findings.filter { it.kind == FindingKind.DEVICE }

            LazyColumn(contentPadding = PaddingValues(16.dp)) {
                item {
                    CsCard(accent = current.color()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text("Nivel general de seguridad", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                                Text(Recommendations.overallText(current), style = MaterialTheme.typography.titleMedium, color = current.color())
                            }
                            LevelBadge(current)
                        }
                        Text(
                            "${s.type.label} · ${Format.dateTime(s.startedAt)} · duración ${s.finishedAt?.let { Format.duration(it - s.startedAt) } ?: "—"}",
                            style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(top = 6.dp)
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatTile("Archivos analizados", s.filesScanned.toString(), CsColors.Blue, Modifier.weight(1f))
                        StatTile("Ocultos", s.hiddenCount.toString(), CsColors.Blue, Modifier.weight(1f))
                        StatTile("Apps revisadas", s.appsScanned.toString(), CsColors.Blue, Modifier.weight(1f))
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatTile("Amenazas confirmadas", s.critical.toString(), if (s.critical > 0) CsColors.Critical else CsColors.Green, Modifier.weight(1f))
                        StatTile("Sospechosos (A/M/B)", "${s.high}/${s.medium}/${s.low}", if (s.high + s.medium > 0) CsColors.Medium else CsColors.Green, Modifier.weight(1f))
                    }
                    Text(
                        "SHA-256 calculado en ${s.filesHashed} archivos · ${s.errors} elementos no legibles",
                        style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(top = 8.dp)
                    )
                    if (s.locations.isNotBlank()) {
                        SectionTitle("Ubicaciones analizadas")
                        Text(s.locations, style = MaterialTheme.typography.bodySmall)
                    }
                    if (s.notes.isNotBlank()) {
                        SectionTitle("Notas")
                        Text(s.notes, style = MaterialTheme.typography.bodySmall, color = CsColors.Medium)
                    }
                    Spacer(Modifier.height(14.dp))
                    Button(
                        onClick = {
                            val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date(s.startedAt))
                            exportLauncher.launch("CyberSentinel-informe-$scanId-$stamp.pdf")
                        },
                        enabled = !exporting, modifier = Modifier.fillMaxWidth().height(50.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CsColors.Blue)
                    ) { Text(if (exporting) "Generando PDF…" else "Exportar informe en PDF", fontWeight = FontWeight.Bold) }

                    SectionTitle("Recomendaciones")
                    d.recommendations.forEachIndexed { i, r ->
                        Text("${i + 1}. $r", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(vertical = 3.dp))
                    }
                    SectionTitle("Amenazas confirmadas (${confirmed.size})")
                    if (confirmed.isEmpty()) Text("Ninguna coincidencia con firmas de malware conocidas.", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                }
                items(confirmed, key = { "c${it.id}" }) { f -> FindingRow(f) { nav.navigate(Routes.finding(f.id)) } }
                item {
                    SectionTitle("Elementos sospechosos (${suspicious.size})")
                    if (suspicious.isEmpty()) Text("Ninguno.", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                }
                items(suspicious, key = { "s${it.id}" }) { f -> FindingRow(f) { nav.navigate(Routes.finding(f.id)) } }
                item { SectionTitle("Configuración del dispositivo") }
                items(device, key = { "d${it.id}" }) { f -> FindingRow(f) { nav.navigate(Routes.finding(f.id)) } }
            }
        }
    }
}

// ============================================================================ CUARENTENA

@Composable
fun QuarantineScreen(nav: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var action by remember { mutableStateOf<Pair<String, QuarantineItem>?>(null) }
    var restoreTarget by remember { mutableStateOf<QuarantineItem?>(null) }
    val quarantined by rememberQuery { Database.get(context).getQuarantine() }

    fun perform(block: (QuarantineManager) -> String) {
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                try { block(QuarantineManager(context)) }
                catch (e: QuarantineManager.QuarantineException) { e.message ?: "No se pudo completar" }
                catch (e: Exception) { "Error: ${e.message}" }
            }
            ScanManager.notifyDataChanged()
            snackbar.showSnackbar(msg)
        }
    }

    val restoreToLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val item = restoreTarget
        restoreTarget = null
        if (uri != null && item != null) perform { it.restoreTo(item, uri); "Archivo restaurado en la ubicación elegida" }
    }

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }, containerColor = CsColors.Background, contentWindowInsets = WindowInsets(0, 0, 0, 0)) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            CsTopBar("Cuarentena", onBack = { nav.popBackStack() }, actions = {
                TextButton(onClick = { nav.navigate(Routes.LOG) }) { Text("Registro") }
            })
            Text(
                "Los archivos en cuarentena se guardan ofuscados dentro del almacenamiento privado de la app: no se pueden abrir ni ejecutar. Nada se borra sin tu confirmación.",
                style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(horizontal = 16.dp)
            )
            val list = quarantined ?: emptyList()
            if (quarantined != null && list.isEmpty()) EmptyState("Cuarentena vacía", "No hay archivos aislados.")
            LazyColumn(contentPadding = PaddingValues(16.dp)) {
                items(list, key = { it.id }) { q ->
                    CsCard(modifier = Modifier.padding(vertical = 4.dp)) {
                        Text(q.originalName, style = MaterialTheme.typography.titleMedium)
                        Text("Desde: ${q.originalLocation}", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                        Text("${Format.dateTime(q.quarantinedAt)} · ${Format.size(q.size)} · ${q.reason}", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                        Text("SHA-256 ${q.sha256}", style = MaterialTheme.typography.labelSmall, color = CsColors.Outline)
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            TextButton(onClick = { action = "restore" to q }) { Text("Restaurar", color = CsColors.Green) }
                            TextButton(onClick = { restoreTarget = q; restoreToLauncher.launch(q.originalName) }) { Text("Restaurar en…", color = CsColors.Blue) }
                            TextButton(onClick = { action = "delete" to q }) { Text("Eliminar", color = CsColors.Critical) }
                        }
                    }
                }
            }
        }
    }

    action?.let { (kind, q) ->
        if (kind == "restore") ConfirmDialog(
            title = "¿Restaurar \"${q.originalName}\"?",
            message = "Volverá a ${q.originalLocation}. Si el archivo es malicioso, podría volver a ser un riesgo.",
            confirmText = "Restaurar",
            onConfirm = { perform { m -> "Restaurado en ${m.restore(q)}" } },
            onDismiss = { action = null }
        ) else ConfirmDialog(
            title = "¿Eliminar definitivamente?",
            message = "\"${q.originalName}\" se borrará para siempre. Esta acción no se puede deshacer.",
            confirmText = "Eliminar", destructive = true,
            onConfirm = { perform { m -> m.deletePermanently(q); "Eliminado definitivamente" } },
            onDismiss = { action = null }
        )
    }
}
