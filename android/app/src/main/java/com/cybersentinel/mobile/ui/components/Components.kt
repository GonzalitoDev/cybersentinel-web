package com.cybersentinel.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.FindingStatus
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.scanner.ScanManager
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.ui.theme.color
import com.cybersentinel.mobile.util.Format
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Ejecuta una consulta en segundo plano y la repite cuando cambian los datos guardados. */
@Composable
fun <T> rememberQuery(vararg keys: Any?, query: suspend () -> T): State<T?> {
    val version by ScanManager.dataVersion.collectAsState()
    return produceState<T?>(initialValue = null, version, *keys) {
        value = withContext(Dispatchers.IO) { query() }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CsTopBar(title: String, onBack: (() -> Unit)? = null, actions: @Composable () -> Unit = {}) {
    TopAppBar(
        title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        navigationIcon = {
            if (onBack != null) IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Volver")
            }
        },
        actions = { actions() },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = CsColors.Background),
        // Los insets del sistema ya los aplica el Scaffold principal.
        windowInsets = WindowInsets(0, 0, 0, 0)
    )
}

@Composable
fun LevelBadge(level: RiskLevel, modifier: Modifier = Modifier) {
    val c = level.color()
    Box(
        modifier
            .clip(RoundedCornerShape(6.dp))
            .background(c.copy(alpha = 0.15f))
            .border(1.dp, c.copy(alpha = 0.6f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(level.label, color = c, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun CsCard(modifier: Modifier = Modifier, onClick: (() -> Unit)? = null, accent: Color? = null, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    Column(
        modifier
            .fillMaxWidth()
            .clip(shape)
            .background(CsColors.Surface)
            .border(1.dp, (accent ?: CsColors.Outline).copy(alpha = if (accent != null) 0.5f else 1f), shape)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(16.dp),
        content = content
    )
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = CsColors.Blue,
        modifier = modifier.padding(top = 18.dp, bottom = 8.dp)
    )
}

@Composable
fun StatTile(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Column(
        modifier
            .clip(RoundedCornerShape(12.dp))
            .background(CsColors.Surface)
            .border(1.dp, CsColors.Outline, RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Text(value, style = MaterialTheme.typography.headlineSmall, color = color)
        Text(label, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, maxLines = 2)
    }
}

@Composable
fun NavRow(icon: ImageVector, title: String, subtitle: String? = null, onClick: () -> Unit) {
    CsCard(onClick = onClick, modifier = Modifier.padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = CsColors.Green, modifier = Modifier.size(24.dp))
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
            }
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, tint = CsColors.TextDim)
        }
    }
}

@Composable
fun FindingRow(f: Finding, onClick: () -> Unit) {
    CsCard(onClick = onClick, modifier = Modifier.padding(vertical = 4.dp), accent = if (f.level.weight >= 3) f.level.color() else null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(f.name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val sub = when (f.kind) {
                    FindingKind.APP -> "${f.packageName ?: ""} · ${f.location}"
                    else -> "${f.title} · ${f.location}"
                }
                Text(sub, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim, maxLines = 2, overflow = TextOverflow.Ellipsis)
                val meta = buildList {
                    if (f.kind == FindingKind.FILE && !f.isDirectory) add(Format.size(f.size))
                    if (f.modifiedAt != null) add(Format.date(f.modifiedAt))
                    if (f.status != FindingStatus.OPEN) add(f.status.label)
                }
                if (meta.isNotEmpty()) Text(meta.joinToString(" · "), style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
            }
            Spacer(Modifier.width(8.dp))
            LevelBadge(f.level)
        }
    }
}

@Composable
fun EmptyState(title: String, message: String, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.size(6.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium, color = CsColors.TextDim)
    }
}

@Composable
fun ConfirmDialog(
    title: String,
    message: String,
    confirmText: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    destructive: Boolean = false
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(message) },
        confirmButton = {
            TextButton(onClick = { onDismiss(); onConfirm() }) {
                Text(confirmText, color = if (destructive) CsColors.Critical else CsColors.Green)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
        containerColor = CsColors.SurfaceHigh
    )
}

@Composable
fun KeyValue(key: String, value: String, mono: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
        Text(key, style = MaterialTheme.typography.bodySmall, color = CsColors.TextDim)
        Text(value, style = if (mono) MaterialTheme.typography.labelSmall else MaterialTheme.typography.bodyMedium)
    }
}
