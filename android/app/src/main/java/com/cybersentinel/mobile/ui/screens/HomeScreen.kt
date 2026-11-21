package com.cybersentinel.mobile.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybersentinel.mobile.Routes
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.FindingStatus
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.ScanType
import com.cybersentinel.mobile.goTab
import com.cybersentinel.mobile.report.Recommendations
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.scanner.StorageAccess
import com.cybersentinel.mobile.ui.components.NavRow
import com.cybersentinel.mobile.ui.components.SectionTitle
import com.cybersentinel.mobile.ui.components.StatTile
import com.cybersentinel.mobile.ui.components.rememberQuery
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.ui.theme.color
import com.cybersentinel.mobile.util.Format
import com.cybersentinel.mobile.util.Prefs

private class HomeData(
    val lastScanText: String?,
    val level: RiskLevel?,
    val confirmed: Int,
    val suspicious: Int,
    val hidden: Int,
    val apps: Int,
    val suspiciousApps: Int,
    val quarantine: Int,
    val signatures: Long,
    val accessText: String,
    val hasAccess: Boolean
)

@Composable
fun HomeScreen(nav: NavHostController) {
    val context = LocalContext.current
    val progress by ScanManager.progress.collectAsState()
    val prefs = remember { Prefs(context) }
    var showWelcome by remember { mutableStateOf(!prefs.onboardingDone) }
    var pendingType by remember { mutableStateOf<ScanType?>(null) }

    val data by rememberQuery {
        val db = Database.get(context)
        val scan = db.latestCompletedScan()
        val findings = scan?.let { db.getFindings(it.id) } ?: emptyList()
        val open = findings.filter { it.status == FindingStatus.OPEN }
        val allFiles = StorageAccess.hasAllFilesAccess(context)
        val folders = StorageAccess.safFolders(context).size
        HomeData(
            lastScanText = scan?.let { "${it.type.label} · ${Format.dateTime(it.finishedAt)}" },
            level = scan?.let { Recommendations.currentLevel(findings) },
            confirmed = open.count { it.level == RiskLevel.CRITICAL },
            suspicious = open.count { it.level.weight in 1..3 },
            hidden = findings.count { it.isHidden },
            apps = scan?.appsScanned ?: 0,
            suspiciousApps = open.count { it.kind == FindingKind.APP && it.level.weight >= RiskLevel.MEDIUM.weight },
            quarantine = db.getQuarantine().size,
            signatures = db.signatureCount(),
            accessText = when {
                allFiles && folders > 0 -> "Todos los archivos + $folders carpeta(s)"
                allFiles -> "Acceso a todos los archivos"
                folders > 0 -> "$folders carpeta(s) autorizada(s)"
                else -> "Sin acceso a archivos"
            },
            hasAccess = allFiles || folders > 0
        )
    }

    fun startScan(type: ScanType) {
        if (type != ScanType.APPS && data?.hasAccess == false) { pendingType = type; return }
        if (ScanManager.start(context, type)) nav.navigate(Routes.SCAN)
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 18.dp, vertical = 12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("CYBER", style = MaterialTheme.typography.headlineSmall, color = CsColors.Green)
            Text("SENTINEL", style = MaterialTheme.typography.headlineSmall, color = CsColors.Blue)
        }
        Text("Protección local · sin conexión", style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
        Spacer(Modifier.height(18.dp))

        // ----------------------------------------------------------- estado
        val d = data
        val level = d?.level
        val ringColor = when {
            progress.running -> CsColors.Blue
            level == null -> CsColors.TextDim
            else -> level.color()
        }
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            StatusRing(color = ringColor, scanning = progress.running, fraction = progress.fraction)
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.width(180.dp)) {
                if (progress.running) {
                    Text(progress.fraction?.let { "${(it * 100).toInt()}%" } ?: "…", style = MaterialTheme.typography.headlineSmall, color = CsColors.Blue)
                    Text(progress.phase, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, textAlign = TextAlign.Center)
                } else {
                    Text(level?.label ?: "SIN DATOS", style = MaterialTheme.typography.headlineSmall, color = ringColor, fontWeight = FontWeight.Bold)
                    Text(
                        level?.let { Recommendations.overallText(it) } ?: "Todavía no hiciste ningún análisis",
                        style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, textAlign = TextAlign.Center
                    )
                }
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            d?.lastScanText?.let { "Último análisis: $it" } ?: "",
            style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim,
            modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center
        )
        progress.lastResult?.takeIf { !progress.running }?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = CsColors.Green, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        }
        Spacer(Modifier.height(16.dp))

        if (progress.running) {
            Button(onClick = { nav.navigate(Routes.SCAN) }, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Text("Ver análisis en curso")
            }
        } else {
            Button(
                onClick = { startScan(ScanType.QUICK) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = CsColors.Green)
            ) { Text("Análisis rápido", fontWeight = FontWeight.Bold) }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = { startScan(ScanType.FULL) }, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Text("Análisis completo", color = CsColors.Blue, fontWeight = FontWeight.Bold)
            }
            Text(
                "Rápido: Descargas, Documentos, Bluetooth, carpetas autorizadas (3 niveles), apps y ajustes. " +
                    "Completo: todo el almacenamiento accesible, apps y ajustes.",
                style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(top = 8.dp)
            )
        }

        // ---------------------------------------------------------- números
        if (d != null && d.lastScanText != null) {
            SectionTitle("Último resultado")
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatTile("Amenazas confirmadas", d.confirmed.toString(), if (d.confirmed > 0) CsColors.Critical else CsColors.Green, Modifier.weight(1f))
                StatTile("Sospechosos pendientes", d.suspicious.toString(), if (d.suspicious > 0) CsColors.Medium else CsColors.Green, Modifier.weight(1f))
            }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatTile("Ocultos encontrados", d.hidden.toString(), CsColors.Blue, Modifier.weight(1f))
                StatTile("Apps revisadas", d.apps.toString(), CsColors.Blue, Modifier.weight(1f))
            }
        }

        SectionTitle("Secciones")
        NavRow(Icons.Filled.Search, "Archivos sospechosos y ocultos", d?.let { "${it.hidden} ocultos en el último análisis" }) { nav.goTab(Routes.FILES) }
        NavRow(Icons.Filled.Build, "Aplicaciones", d?.let { "${it.suspiciousApps} apps de riesgo medio o mayor" }) { nav.goTab(Routes.APPS) }
        NavRow(Icons.Filled.Lock, "Cuarentena", d?.let { "${it.quarantine} archivo(s) aislados" }) { nav.navigate(Routes.QUARANTINE) }
        NavRow(Icons.AutoMirrored.Filled.List, "Historial e informes", "Resultados anteriores y exportación PDF") { nav.goTab(Routes.HISTORY) }

        SectionTitle("Estado de la protección")
        Text("Acceso a archivos: ${d?.accessText ?: "…"}", style = MaterialTheme.typography.bodyMedium)
        Text("Firmas de malware en la base local: ${d?.signatures ?: "…"}", style = MaterialTheme.typography.bodyMedium)
        if (d != null && d.signatures <= 1) {
            Text(
                "Sólo está la firma de prueba EICAR. Importá una base de hashes en Ajustes para detectar malware conocido.",
                style = MaterialTheme.typography.bodySmall, color = CsColors.Medium
            )
        }
        TextButton(onClick = { nav.goTab(Routes.SETTINGS) }) { Text("Configurar accesos y firmas") }
        Spacer(Modifier.height(24.dp))
    }

    if (pendingType != null) {
        AlertDialog(
            onDismissRequest = { pendingType = null },
            title = { Text("No hay acceso a archivos") },
            text = {
                Text(
                    "Para analizar archivos tenés que autorizar carpetas (por ejemplo, subcarpetas de Descargas) o activar " +
                        "\"Acceso a todos los archivos\". Sin eso, sólo se pueden analizar las apps y la configuración del teléfono."
                )
            },
            confirmButton = {
                TextButton(onClick = { pendingType = null; nav.goTab(Routes.SETTINGS) }) { Text("Configurar acceso") }
            },
            dismissButton = {
                TextButton(onClick = {
                    pendingType = null
                    if (ScanManager.start(context, ScanType.APPS)) nav.navigate(Routes.SCAN)
                }) { Text("Analizar sólo apps") }
            },
            containerColor = CsColors.SurfaceHigh
        )
    }

    if (showWelcome) {
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Bienvenido a CyberSentinel") },
            text = {
                Text(
                    "• Todo el análisis se hace en tu teléfono. La app no tiene permiso de Internet: no puede enviar nada.\n\n" +
                        "• Sólo accede a lo que vos autorizás: carpetas elegidas o \"Acceso a todos los archivos\" (opcional).\n\n" +
                        "• Nunca borra nada por su cuenta: siempre te pide confirmación y lo registra.\n\n" +
                        "• \"CRÍTICO\" sólo aparece cuando un archivo coincide exactamente con una firma de malware conocida."
                )
            },
            confirmButton = {
                TextButton(onClick = { prefs.onboardingDone = true; showWelcome = false }) { Text("Entendido") }
            },
            containerColor = CsColors.SurfaceHigh
        )
    }
}

@Composable
private fun StatusRing(color: Color, scanning: Boolean, fraction: Float?) {
    val transition = rememberInfiniteTransition(label = "ring")
    val rotation by transition.animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(2400, easing = LinearEasing)), label = "rot"
    )
    val pulse by transition.animateFloat(
        initialValue = 0.35f, targetValue = 0.8f,
        animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse), label = "pulse"
    )
    Canvas(Modifier.size(220.dp)) {
        val stroke = 10.dp.toPx()
        val inset = stroke / 2 + 6.dp.toPx()
        val arcSize = Size(size.width - inset * 2, size.height - inset * 2)
        val topLeft = Offset(inset, inset)
        // pista
        drawArc(color.copy(alpha = 0.12f), 0f, 360f, false, topLeft, arcSize, style = Stroke(stroke))
        if (scanning) {
            if (fraction != null) {
                drawArc(color, -90f, 360f * fraction, false, topLeft, arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
            }
            drawArc(color.copy(alpha = 0.5f), rotation, 50f, false, topLeft, arcSize, style = Stroke(stroke / 2, cap = StrokeCap.Round))
        } else {
            drawArc(color.copy(alpha = pulse), 0f, 360f, false, topLeft, arcSize, style = Stroke(stroke))
        }
        // anillo interior decorativo
        val inner = inset + 22.dp.toPx()
        drawArc(
            color.copy(alpha = 0.25f), -rotation / 2, 300f, false,
            Offset(inner, inner), Size(size.width - inner * 2, size.height - inner * 2),
            style = Stroke(1.5.dp.toPx())
        )
    }
}
