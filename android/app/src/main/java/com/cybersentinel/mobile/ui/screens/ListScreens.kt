package com.cybersentinel.mobile.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybersentinel.mobile.Routes
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.ScanRecord
import com.cybersentinel.mobile.data.ScanStatus
import com.cybersentinel.mobile.data.ScanType
import com.cybersentinel.mobile.scanner.Origin
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.ui.components.ConfirmDialog
import com.cybersentinel.mobile.ui.components.CsCard
import com.cybersentinel.mobile.ui.components.CsTopBar
import com.cybersentinel.mobile.ui.components.EmptyState
import com.cybersentinel.mobile.ui.components.FindingRow
import com.cybersentinel.mobile.ui.components.LevelBadge
import com.cybersentinel.mobile.ui.components.rememberQuery
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.ui.theme.color
import com.cybersentinel.mobile.util.Format
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope

// ============================================================================ ARCHIVOS

@Composable
fun FilesScreen(nav: NavHostController) {
    val context = LocalContext.current
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var minLevel by rememberSaveable { mutableStateOf(RiskLevel.LOW) }

    val data by rememberQuery {
        val db = Database.get(context)
        val scan = db.latestCompletedScan(ScanType.QUICK, ScanType.FULL)
            ?: db.getScans().firstOrNull { it.type != ScanType.APPS && it.status == ScanStatus.CANCELLED }
        scan to (scan?.let { db.getFindings(it.id, kind = FindingKind.FILE) } ?: emptyList())
    }
    val scan = data?.first
    val all = data?.second ?: emptyList()

    Column(Modifier.fillMaxSize()) {
        CsTopBar("Archivos")
        TabRow(selectedTabIndex = tab, containerColor = CsColors.Background, contentColor = CsColors.Green) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Sospechosos (${all.count { it.level != RiskLevel.SAFE }})") })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Ocultos (${all.count { it.isHidden }})") })
        }
        if (scan == null) {
            EmptyState("Sin análisis de archivos", "Hacé un análisis rápido o completo desde Inicio para ver resultados.")
            return@Column
        }
        Text(
            "${scan.type.label} · ${Format.dateTime(scan.finishedAt)} · ${scan.filesScanned} archivos analizados",
            style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
        )
        if (tab == 0) {
            LazyRow(contentPadding = PaddingValues(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(listOf(RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)) { l ->
                    FilterChip(
                        selected = minLevel == l, onClick = { minLevel = l },
                        label = { Text(if (l == RiskLevel.LOW) "Todos" else "${l.label} o más") },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = l.color().copy(alpha = 0.2f), selectedLabelColor = l.color())
                    )
                }
            }
            val list = all.filter { it.level.weight >= minLevel.weight }
            if (list.isEmpty()) EmptyState("Nada para mostrar", "No hay archivos con ese nivel de riesgo en el último análisis.")
            LazyColumn(contentPadding = PaddingValues(16.dp)) {
                items(list, key = { it.id }) { f -> FindingRow(f) { nav.navigate(Routes.finding(f.id)) } }
            }
        } else {
            val list = all.filter { it.isHidden }
            if (list.isEmpty()) EmptyState("Sin elementos ocultos", "No se encontraron archivos ni carpetas ocultas en las ubicaciones analizadas.")
            LazyColumn(contentPadding = PaddingValues(16.dp)) {
                items(list, key = { it.id }) { f -> FindingRow(f) { nav.navigate(Routes.finding(f.id)) } }
            }
        }
    }
}

// ============================================================================ APPS

@Composable
fun AppsScreen(nav: NavHostController) {
    val context = LocalContext.current
    val progress by ScanManager.progress.collectAsState()
    var filter by rememberSaveable { mutableIntStateOf(0) }
    var query by rememberSaveable { mutableStateOf("") }

    val data by rememberQuery {
        val db = Database.get(context)
        val scan = db.latestCompletedScan()
        scan to (scan?.let { db.getFindings(it.id, kind = FindingKind.APP) } ?: emptyList())
    }
    val scan = data?.first
    val all = data?.second ?: emptyList()

    Column(Modifier.fillMaxSize()) {
        CsTopBar("Aplicaciones", actions = {
            IconButton(enabled = !progress.running, onClick = {
                if (ScanManager.start(context, ScanType.APPS)) nav.navigate(Routes.SCAN)
            }) { Icon(Icons.Filled.Refresh, contentDescription = "Analizar apps ahora") }
        })
        if (scan == null) {
            EmptyState("Sin análisis de apps", "Tocá el botón de actualizar para analizar las aplicaciones instaladas.")
            return@Column
        }
        Text(
            "${all.size} apps visibles revisadas · ${Format.dateTime(scan.finishedAt)}",
            style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(horizontal = 16.dp)
        )
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true,
            label = { Text("Buscar por nombre o paquete") },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)
        )
        val filters = listOf("Sospechosas", "Fuera de tiendas", "Accesibilidad / admin / SMS", "Todas")
        LazyRow(contentPadding = PaddingValues(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(filters.size) { i ->
                FilterChip(selected = filter == i, onClick = { filter = i }, label = { Text(filters[i]) })
            }
        }
        val list = all.filter { f ->
            val q = query.trim().lowercase()
            (q.isEmpty() || f.name.lowercase().contains(q) || (f.packageName ?: "").lowercase().contains(q)) && when (filter) {
                0 -> f.level != RiskLevel.SAFE
                1 -> f.realType == Origin.SIDELOADED.name || f.realType == Origin.UNKNOWN.name
                2 -> f.reasons.any { r -> r.contains("accesibilidad", true) || r.contains("administra", true) || r.contains("SMS") }
                else -> true
            }
        }
        if (list.isEmpty()) EmptyState("Nada para mostrar", "Ninguna app coincide con este filtro.")
        LazyColumn(contentPadding = PaddingValues(16.dp)) {
            items(list, key = { it.id }) { f -> FindingRow(f) { nav.navigate(Routes.finding(f.id)) } }
        }
    }
}

// ============================================================================ HISTORIAL

@Composable
fun HistoryScreen(nav: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var toDelete by remember { mutableStateOf<ScanRecord?>(null) }
    val scans by rememberQuery { Database.get(context).getScans() }

    Column(Modifier.fillMaxSize()) {
        CsTopBar("Historial de análisis", actions = {
            IconButton(onClick = { nav.navigate(Routes.LOG) }) {
                Text("Registro", color = CsColors.Blue, style = MaterialTheme.typography.labelSmall)
            }
        })
        val list = scans ?: emptyList()
        if (scans != null && list.isEmpty()) EmptyState("Sin historial", "Todavía no hiciste ningún análisis.")
        LazyColumn(contentPadding = PaddingValues(16.dp)) {
            items(list, key = { it.id }) { s ->
                CsCard(onClick = { nav.navigate(Routes.report(s.id)) }, modifier = Modifier.padding(vertical = 4.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("#${s.id} · ${s.type.label}", style = MaterialTheme.typography.titleMedium)
                            Text(Format.dateTime(s.startedAt) + statusSuffix(s.status), style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
                            Text(
                                "${s.filesScanned} archivos · ${s.appsScanned} apps · ${s.critical} confirmadas · ${s.high + s.medium + s.low} sospechosos",
                                style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            LevelBadge(s.overallLevel)
                            IconButton(onClick = { toDelete = s }, enabled = s.status != ScanStatus.RUNNING) {
                                Icon(Icons.Filled.Delete, contentDescription = "Borrar del historial", tint = CsColors.TextDim)
                            }
                        }
                    }
                }
            }
        }
    }

    toDelete?.let { s ->
        ConfirmDialog(
            title = "¿Borrar el análisis #${s.id}?",
            message = "Se borra el registro y sus resultados del historial. No afecta archivos ni la cuarentena.",
            confirmText = "Borrar", destructive = true,
            onConfirm = {
                scope.launch(Dispatchers.IO) {
                    val db = Database.get(context)
                    db.deleteScan(s.id)
                    db.log("Historial", "Borrado el análisis #${s.id}")
                    ScanManager.notifyDataChanged()
                }
            },
            onDismiss = { toDelete = null }
        )
    }
}

private fun statusSuffix(s: ScanStatus) = when (s) {
    ScanStatus.COMPLETED -> ""
    ScanStatus.CANCELLED -> " · cancelado (parcial)"
    ScanStatus.RUNNING -> " · en curso"
    ScanStatus.FAILED -> " · con errores"
}

// ============================================================================ REGISTRO

@Composable
fun LogScreen(nav: NavHostController) {
    val context = LocalContext.current
    val log by rememberQuery { Database.get(context).getLog() }
    Column(Modifier.fillMaxSize()) {
        CsTopBar("Registro de acciones", onBack = { nav.popBackStack() })
        val list = log ?: emptyList()
        if (log != null && list.isEmpty()) EmptyState("Registro vacío", "Acá aparecen análisis, cuarentenas, restauraciones y exportaciones.")
        LazyColumn(contentPadding = PaddingValues(16.dp)) {
            items(list, key = { it.id }) { e ->
                Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Text("${Format.dateTime(e.timestamp)} · ${e.action}", style = MaterialTheme.typography.labelSmall, color = CsColors.Green)
                    Text(e.detail, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}
