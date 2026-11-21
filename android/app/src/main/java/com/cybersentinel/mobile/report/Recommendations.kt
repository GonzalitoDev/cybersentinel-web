package com.cybersentinel.mobile.report

import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.FindingStatus
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.ScanRecord
import com.cybersentinel.mobile.data.ScanStatus

object Recommendations {

    /** Texto del nivel general, calculado SÓLO a partir de los hallazgos (sin porcentajes inventados). */
    fun overallText(level: RiskLevel): String = when (level) {
        RiskLevel.CRITICAL -> "En riesgo: hay amenazas confirmadas"
        RiskLevel.HIGH -> "Atención: hay elementos muy sospechosos"
        RiskLevel.MEDIUM -> "Revisar: hay elementos que requieren revisión"
        RiskLevel.LOW -> "Aceptable: sólo elementos poco habituales"
        RiskLevel.SAFE -> "Sin amenazas conocidas detectadas"
    }

    /** Nivel actual considerando sólo hallazgos pendientes (no en cuarentena, ni marcados como confiables). */
    fun currentLevel(findings: List<Finding>): RiskLevel =
        findings.filter { it.status == FindingStatus.OPEN && it.level != RiskLevel.SAFE }
            .maxByOrNull { it.level.weight }?.level ?: RiskLevel.SAFE

    fun build(scan: ScanRecord, findings: List<Finding>, signatureCount: Long, hasFileAccess: Boolean): List<String> {
        val out = mutableListOf<String>()
        val open = findings.filter { it.status == FindingStatus.OPEN }
        val files = open.filter { it.kind == FindingKind.FILE }
        val apps = open.filter { it.kind == FindingKind.APP }
        val device = open.filter { it.kind == FindingKind.DEVICE && it.level != RiskLevel.SAFE }

        val critFiles = files.count { it.level == RiskLevel.CRITICAL }
        val critApps = apps.count { it.level == RiskLevel.CRITICAL }
        if (critFiles > 0) out += "Poné en cuarentena los $critFiles archivo(s) con amenaza confirmada. No los abras ni los instales."
        if (critApps > 0) out += "Desinstalá las $critApps app(s) cuyo APK coincide con malware conocido. Si no te deja, quitale primero el permiso de administrador del dispositivo."

        val highFiles = files.filter { it.level == RiskLevel.HIGH }
        if (highFiles.isNotEmpty()) out += "Revisá los ${highFiles.size} archivo(s) de riesgo ALTO (extensiones engañosas, ejecutables ocultos). Si no los reconocés, ponelos en cuarentena."
        val highApps = apps.filter { it.level == RiskLevel.HIGH }
        if (highApps.isNotEmpty()) out += "Revisá las ${highApps.size} app(s) de riesgo ALTO: ${highApps.take(5).joinToString(", ") { it.name }}. Si no las instalaste vos o no sabés para qué sirven, desinstalalas."

        if (apps.any { a -> a.reasons.any { it.contains("accesibilidad ACTIVO") } })
            out += "Desactivá la accesibilidad de las apps que no la necesiten (Ajustes > Accesibilidad > Apps descargadas)."
        if (apps.any { a -> a.reasons.any { it.contains("administrador ACTIVO") } })
            out += "Quitá el permiso de administrador del dispositivo a las apps que no lo necesiten (Ajustes > Seguridad > Apps de administración del dispositivo)."
        if (apps.any { a -> a.reasons.any { it.contains("acceso a SMS") } })
            out += "Revocá el acceso a SMS de las apps que no sean tu app de mensajes."
        if (apps.any { it.realType == "SIDELOADED" && it.level.weight >= RiskLevel.MEDIUM.weight })
            out += "Desactivá \"Instalar apps desconocidas\" para los navegadores y gestores de archivos que no uses para eso."

        if (files.any { it.title.contains("macros") }) out += "No habilites macros en documentos de Office salvo que confíes en quien te los envió."
        if (files.any { it.realType?.contains("APK") == true }) out += "Borrá los instaladores APK que ya no necesites; instalá apps preferentemente desde tiendas oficiales."

        for (d in device) {
            when {
                d.title.contains("bloqueo", ignoreCase = true) -> out += "Configurá un bloqueo de pantalla (PIN, patrón o contraseña)."
                d.title.contains("Depuración USB") -> out += "Desactivá la depuración USB (Ajustes > Opciones de desarrollador)."
                d.title.contains("Parche") -> out += "Instalá las actualizaciones del sistema disponibles."
                d.title.contains("desarrollador") -> out += "Si no usás las opciones de desarrollador, desactivalas."
            }
        }

        if (signatureCount <= 1) out += "La base de firmas sólo tiene la firma de prueba EICAR. Importá una base de hashes (por ejemplo, de MalwareBazaar) desde Ajustes para detectar malware conocido."
        if (!hasFileAccess && scan.filesScanned == 0) out += "No se analizaron archivos: agregá carpetas o activá \"Acceso a todos los archivos\" en Ajustes."
        if (scan.status == ScanStatus.CANCELLED) out += "El análisis se canceló; ejecutá uno completo para tener resultados totales."
        if (out.isEmpty()) out += "No se encontraron problemas. Mantené el sistema actualizado y repetí el análisis periódicamente."
        return out
    }
}
