package com.cybersentinel.mobile.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.cybersentinel.mobile.data.RiskLevel

object CsColors {
    val Background = Color(0xFF0A0F16)
    val Surface = Color(0xFF101923)
    val SurfaceHigh = Color(0xFF16222F)
    val Outline = Color(0xFF223346)
    val Green = Color(0xFF00E5A0)
    val Blue = Color(0xFF38BDF8)
    val Text = Color(0xFFE6EDF3)
    val TextDim = Color(0xFF8B9BAD)

    val Critical = Color(0xFFFF4D6D)
    val High = Color(0xFFFF8A3D)
    val Medium = Color(0xFFFFC53D)
    val Low = Color(0xFF7DD3FC)
    val Safe = Green
}

fun RiskLevel.color(): Color = when (this) {
    RiskLevel.CRITICAL -> CsColors.Critical
    RiskLevel.HIGH -> CsColors.High
    RiskLevel.MEDIUM -> CsColors.Medium
    RiskLevel.LOW -> CsColors.Low
    RiskLevel.SAFE -> CsColors.Safe
}

private val scheme = darkColorScheme(
    primary = CsColors.Green,
    onPrimary = Color(0xFF00281B),
    secondary = CsColors.Blue,
    onSecondary = Color(0xFF00243A),
    tertiary = CsColors.Blue,
    background = CsColors.Background,
    onBackground = CsColors.Text,
    surface = CsColors.Surface,
    onSurface = CsColors.Text,
    surfaceVariant = CsColors.SurfaceHigh,
    onSurfaceVariant = CsColors.TextDim,
    surfaceContainer = CsColors.Surface,
    surfaceContainerHigh = CsColors.SurfaceHigh,
    surfaceContainerHighest = CsColors.SurfaceHigh,
    surfaceContainerLow = CsColors.Surface,
    outline = CsColors.Outline,
    outlineVariant = CsColors.Outline,
    error = CsColors.Critical
)

private val typography = Typography(
    headlineSmall = TextStyle(fontWeight = FontWeight.Bold, fontSize = 22.sp, letterSpacing = 0.2.sp),
    titleLarge = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 20.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 16.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 17.sp),
    labelSmall = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 11.sp, letterSpacing = 0.5.sp)
)

@Composable
fun CyberSentinelTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = scheme, typography = typography, content = content)
}
