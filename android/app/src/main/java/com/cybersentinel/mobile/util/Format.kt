package com.cybersentinel.mobile.util

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Format {
    private val dateTime = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale("es", "AR"))
    private val dateOnly = SimpleDateFormat("dd/MM/yyyy", Locale("es", "AR"))

    fun dateTime(ms: Long?): String = if (ms == null || ms <= 0) "no disponible" else synchronized(dateTime) { dateTime.format(Date(ms)) }
    fun date(ms: Long?): String = if (ms == null || ms <= 0) "no disponible" else synchronized(dateOnly) { dateOnly.format(Date(ms)) }

    fun size(bytes: Long?): String {
        if (bytes == null || bytes < 0) return "no disponible"
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var value = bytes / 1024.0
        var i = 0
        while (value >= 1024 && i < units.size - 1) { value /= 1024; i++ }
        return String.format(Locale.US, "%.1f %s", value, units[i])
    }

    fun duration(ms: Long): String {
        val s = ms / 1000
        return if (s < 60) "${s}s" else "${s / 60}m ${s % 60}s"
    }
}

/** Preferencias del usuario (sólo locales). */
class Prefs(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("cybersentinel_prefs", Context.MODE_PRIVATE)

    /** Tamaño máximo (MB) de archivo para calcular SHA-256. Los más grandes se analizan sólo por encabezado. */
    var maxHashMb: Int
        get() = sp.getInt("max_hash_mb", 100)
        set(v) = sp.edit().putInt("max_hash_mb", v.coerceIn(5, 2048)).apply()

    var includeSystemApps: Boolean
        get() = sp.getBoolean("include_system_apps", false)
        set(v) = sp.edit().putBoolean("include_system_apps", v).apply()

    var onboardingDone: Boolean
        get() = sp.getBoolean("onboarding_done", false)
        set(v) = sp.edit().putBoolean("onboarding_done", v).apply()
}
