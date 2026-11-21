package com.cybersentinel.mobile.data

/**
 * Niveles de riesgo. El orden importa: se usa `weight` para comparar.
 * CRÍTICO se reserva para amenazas CONFIRMADAS (coincidencia exacta de firma SHA-256).
 */
enum class RiskLevel(val label: String, val weight: Int) {
    SAFE("SEGURO", 0),
    LOW("BAJO", 1),
    MEDIUM("MEDIO", 2),
    HIGH("ALTO", 3),
    CRITICAL("CRÍTICO", 4);

    companion object {
        fun fromName(name: String?): RiskLevel = entries.firstOrNull { it.name == name } ?: SAFE
        fun max(a: RiskLevel, b: RiskLevel): RiskLevel = if (a.weight >= b.weight) a else b
    }
}

enum class FindingKind { FILE, APP, DEVICE }

enum class FindingStatus(val label: String) {
    OPEN("Pendiente"),
    QUARANTINED("En cuarentena"),
    IGNORED("Marcado como confiable"),
    RESTORED("Restaurado"),
    DELETED("Eliminado"),
    UNINSTALLED("Desinstalada");

    companion object {
        fun fromName(name: String?): FindingStatus = entries.firstOrNull { it.name == name } ?: OPEN
    }
}

enum class ScanType(val label: String) {
    QUICK("Análisis rápido"),
    FULL("Análisis completo"),
    APPS("Análisis de aplicaciones");

    companion object {
        fun fromName(name: String?): ScanType = entries.firstOrNull { it.name == name } ?: QUICK
    }
}

enum class ScanStatus { RUNNING, COMPLETED, CANCELLED, FAILED;
    companion object {
        fun fromName(name: String?): ScanStatus = entries.firstOrNull { it.name == name } ?: FAILED
    }
}

data class Finding(
    val id: Long = 0,
    val scanId: Long,
    val kind: FindingKind,
    val level: RiskLevel,
    val title: String,
    val name: String,
    val location: String,
    /** Ruta absoluta (modo archivo) o URI de documento SAF. */
    val uri: String? = null,
    /** "FILE" o "SAF": indica cómo se accede al elemento. */
    val storageKind: String? = null,
    /** Carpeta que contiene el archivo (ruta o URI de documento SAF), para poder restaurarlo. */
    val parentUri: String? = null,
    val size: Long? = null,
    val createdAt: Long? = null,
    val modifiedAt: Long? = null,
    val sha256: String? = null,
    val realType: String? = null,
    val packageName: String? = null,
    val reasons: List<String> = emptyList(),
    val isHidden: Boolean = false,
    val isDirectory: Boolean = false,
    val status: FindingStatus = FindingStatus.OPEN
)

data class ScanRecord(
    val id: Long = 0,
    val type: ScanType,
    val startedAt: Long,
    val finishedAt: Long? = null,
    val status: ScanStatus = ScanStatus.RUNNING,
    val filesScanned: Int = 0,
    val filesHashed: Int = 0,
    val hiddenCount: Int = 0,
    val appsScanned: Int = 0,
    val critical: Int = 0,
    val high: Int = 0,
    val medium: Int = 0,
    val low: Int = 0,
    val errors: Int = 0,
    val locations: String = "",
    val overallLevel: RiskLevel = RiskLevel.SAFE,
    val notes: String = ""
)

data class QuarantineItem(
    val id: Long = 0,
    val originalName: String,
    val originalLocation: String,
    /** Ruta absoluta original (modo FILE) o URI del documento (modo SAF). */
    val originalUri: String,
    /** Carpeta padre: ruta (FILE) o URI de documento de la carpeta (SAF). */
    val parentUri: String,
    val storageKind: String,
    val mime: String?,
    val sha256: String,
    val size: Long,
    val quarantinedAt: Long,
    val storedFile: String,
    val reason: String,
    val findingId: Long?
)

data class LogEntry(val id: Long, val timestamp: Long, val action: String, val detail: String)

data class Signature(val sha256: String, val name: String, val source: String, val addedAt: Long)
