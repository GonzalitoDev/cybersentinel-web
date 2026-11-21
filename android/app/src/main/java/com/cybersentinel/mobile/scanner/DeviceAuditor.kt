package com.cybersentinel.mobile.scanner

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.RiskLevel
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit

/** Revisa la configuración de seguridad del teléfono con APIs públicas de Android. */
object DeviceAuditor {

    fun audit(context: Context, scanId: Long): List<Finding> {
        val out = mutableListOf<Finding>()
        fun add(level: RiskLevel, title: String, reason: String) {
            out += Finding(
                scanId = scanId, kind = FindingKind.DEVICE, level = level, title = title,
                name = title, location = "Configuración del dispositivo", reasons = listOf(reason)
            )
        }

        // Bloqueo de pantalla
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (km.isDeviceSecure) add(RiskLevel.SAFE, "Bloqueo de pantalla activo", "El teléfono tiene PIN, patrón, contraseña o biometría configurados.")
        else add(RiskLevel.MEDIUM, "Sin bloqueo de pantalla", "Cualquiera que tome el teléfono puede acceder a tus datos. Configurá un PIN, patrón o contraseña.")

        // Opciones de desarrollador / depuración USB
        val dev = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) }.getOrDefault(0) == 1
        val adb = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) }.getOrDefault(0) == 1
        if (adb) add(RiskLevel.MEDIUM, "Depuración USB activa", "Con la depuración USB activa, una computadora conectada puede instalar apps o extraer datos. Desactivala si no la usás.")
        else if (dev) add(RiskLevel.LOW, "Opciones de desarrollador activadas", "Las opciones de desarrollador están activas. Si no las usás, desactivalas.")
        else add(RiskLevel.SAFE, "Depuración USB desactivada", "La depuración USB está desactivada.")

        // Parche de seguridad
        val patch = Build.VERSION.SECURITY_PATCH
        val patchDate = runCatching { SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch) }.getOrNull()
        if (patchDate != null) {
            val days = TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - patchDate.time)
            when {
                days > 365 -> add(RiskLevel.MEDIUM, "Parche de seguridad desactualizado", "El último parche de seguridad es del $patch (hace más de un año). Buscá actualizaciones del sistema.")
                days > 180 -> add(RiskLevel.LOW, "Parche de seguridad antiguo", "El último parche de seguridad es del $patch (hace más de 6 meses).")
                else -> add(RiskLevel.SAFE, "Parche de seguridad reciente", "Parche de seguridad: $patch.")
            }
        }

        add(RiskLevel.SAFE, "Versión de Android", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) — ${Build.MANUFACTURER} ${Build.MODEL}.")
        return out
    }
}
