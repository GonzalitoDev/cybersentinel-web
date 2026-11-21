package com.cybersentinel.mobile.ui.screens

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
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybersentinel.mobile.Routes
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.ui.components.ConfirmDialog
import com.cybersentinel.mobile.ui.components.CsTopBar
import com.cybersentinel.mobile.ui.components.StatTile
import com.cybersentinel.mobile.ui.theme.CsColors

@Composable
fun ScanScreen(nav: NavHostController) {
    val p by ScanManager.progress.collectAsState()
    var confirmCancel by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        CsTopBar(if (p.running) (p.type?.label ?: "Análisis") else "Análisis", onBack = { nav.popBackStack() })
        Column(Modifier.fillMaxSize().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            if (p.running) {
                Box(contentAlignment = Alignment.Center, modifier = Modifier.size(200.dp)) {
                    val f = p.fraction
                    if (f != null) {
                        CircularProgressIndicator(
                            progress = { f }, modifier = Modifier.size(200.dp), strokeWidth = 10.dp,
                            color = CsColors.Green, trackColor = CsColors.Green.copy(alpha = 0.12f)
                        )
                    } else {
                        CircularProgressIndicator(modifier = Modifier.size(200.dp), strokeWidth = 10.dp, color = CsColors.Blue)
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(f?.let { "${(it * 100).toInt()}%" } ?: "…", style = MaterialTheme.typography.headlineSmall, color = CsColors.Green)
                        if (p.total > 0) Text("${p.current} / ${p.total}", style = MaterialTheme.typography.labelSmall, color = CsColors.TextDim)
                    }
                }
                Spacer(Modifier.height(20.dp))
                Text(p.phase, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                Text(
                    p.currentItem, style = MaterialTheme.typography.labelSmall, color = CsColors.TextDim,
                    maxLines = 2, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(12.dp))
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = CsColors.Blue, trackColor = CsColors.Outline)
                Spacer(Modifier.height(20.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatTile("Archivos", p.filesScanned.toString(), CsColors.Blue, Modifier.weight(1f))
                    StatTile("Apps", p.appsScanned.toString(), CsColors.Blue, Modifier.weight(1f))
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatTile("Confirmadas", p.confirmed.toString(), if (p.confirmed > 0) CsColors.Critical else CsColors.Green, Modifier.weight(1f))
                    StatTile("Sospechosos", p.suspicious.toString(), if (p.suspicious > 0) CsColors.Medium else CsColors.Green, Modifier.weight(1f))
                }
                Spacer(Modifier.height(24.dp))
                OutlinedButton(onClick = { confirmCancel = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("Cancelar análisis", color = CsColors.Critical)
                }
                Text(
                    "Podés salir de esta pantalla: el análisis sigue mientras la app esté abierta.",
                    style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, modifier = Modifier.padding(top = 8.dp)
                )
            } else {
                Spacer(Modifier.height(40.dp))
                Text(p.lastResult ?: "No hay ningún análisis en curso.", style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
                Spacer(Modifier.height(20.dp))
                p.lastFinishedScanId?.let { id ->
                    Button(onClick = {
                        nav.navigate(Routes.report(id)) { popUpTo(Routes.SCAN) { inclusive = true } }
                    }, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                        Text("Ver informe", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }

    if (confirmCancel) {
        ConfirmDialog(
            title = "¿Cancelar el análisis?",
            message = "Se guardarán los resultados obtenidos hasta ahora, marcados como parciales.",
            confirmText = "Cancelar análisis",
            destructive = true,
            onConfirm = { ScanManager.cancel() },
            onDismiss = { confirmCancel = false }
        )
    }
}
