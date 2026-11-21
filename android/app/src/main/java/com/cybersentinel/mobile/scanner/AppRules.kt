package com.cybersentinel.mobile.scanner

import android.content.pm.ApplicationInfo
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.Signature

enum class Origin(val label: String) {
    STORE("Tienda oficial"),
    SIDELOADED("Fuera de tiendas oficiales"),
    UNKNOWN("Origen no informado"),
    SYSTEM("Aplicación del sistema"),
    APK_FILE("Archivo APK (no instalado)")
}

/** Hechos verificables sobre una app (instalada o archivo APK). Las reglas sólo trabajan sobre esto. */
data class AppFacts(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val origin: Origin,
    val sourceLabel: String,
    val requested: List<String>,
    val granted: Set<String>,
    val declaresAccessibility: Boolean = false,
    val accessibilityEnabled: Boolean = false,
    val declaresAdmin: Boolean = false,
    val adminActive: Boolean = false,
    val declaresNotificationListener: Boolean = false,
    val notificationListenerEnabled: Boolean = false,
    val isDefaultSms: Boolean = false,
    val hasLauncher: Boolean = true,
    val category: Int = ApplicationInfo.CATEGORY_UNDEFINED,
    val firstInstall: Long? = null,
    val lastUpdate: Long? = null,
    val apkPath: String? = null,
    val apkSize: Long? = null,
    val sha256: String? = null,
    val signatureMatch: Signature? = null,
    val trusted: Boolean = false
)

data class Verdict(val level: RiskLevel, val reasons: List<String>)

object AppRules {

    private val SIMPLE_UTILITY_WORDS = listOf(
        "linterna", "flashlight", "torch", "calculadora", "calculator", "wallpaper", "fondo de pantalla",
        "fondos de pantalla", "brujula", "brújula", "compass", "lector qr", "qr scanner", "qr reader", "escaner qr", "escáner qr"
    )

    fun evaluate(f: AppFacts): Verdict {
        var level = RiskLevel.SAFE
        val reasons = mutableListOf<String>()
        fun add(l: RiskLevel, text: String) {
            level = RiskLevel.max(level, l)
            reasons += "[${l.label}] $text"
        }

        // 1) Amenaza confirmada: hash idéntico a una firma de malware conocida.
        f.signatureMatch?.let {
            add(RiskLevel.CRITICAL, "El SHA-256 del APK coincide con una firma conocida: ${it.name} (fuente: ${it.source}).")
        }

        val isSystem = f.origin == Origin.SYSTEM
        val outsideStore = f.origin == Origin.SIDELOADED || f.origin == Origin.APK_FILE
        // Para archivos APK no instalados se evalúa lo que la app PEDIRÍA; para instaladas, lo concedido
        // (más los permisos especiales, cuyo estado real no es consultable por otras apps).
        val special = setOf(PermissionCatalog.OVERLAY, PermissionCatalog.INSTALL)
        val effective: Set<String> =
            if (f.origin == Origin.APK_FILE) f.requested.toSet()
            else f.granted + f.requested.filter { it in special }
        val verb = if (f.origin == Origin.APK_FILE) "solicita" else "tiene concedido"

        val hasSms = effective.any { it in PermissionCatalog.SMS }
        val hasCalls = effective.any { it in PermissionCatalog.CALLS }
        val hasContacts = effective.any { it in PermissionCatalog.CONTACTS }
        val hasMic = PermissionCatalog.MIC in effective
        val hasOverlay = PermissionCatalog.OVERLAY in effective
        val hasInstall = PermissionCatalog.INSTALL in effective
        val sensitiveCount = effective.count { PermissionCatalog.isSensitive(it) }

        if (!isSystem) {
            // 2) Administración del dispositivo
            if (f.adminActive) {
                add(if (outsideStore) RiskLevel.HIGH else RiskLevel.MEDIUM,
                    "Es administrador ACTIVO del dispositivo: puede bloquear o borrar el teléfono y dificultar su desinstalación.")
            } else if (f.declaresAdmin) {
                add(RiskLevel.LOW, "Puede pedir permisos de administración del dispositivo (todavía no activos).")
            }

            // 3) Accesibilidad
            if (f.accessibilityEnabled) {
                add(if (outsideStore) RiskLevel.HIGH else RiskLevel.MEDIUM,
                    "Tiene un servicio de accesibilidad ACTIVO: puede leer todo lo que aparece en pantalla y tocar por vos.")
            } else if (f.declaresAccessibility) {
                add(if (outsideStore) RiskLevel.MEDIUM else RiskLevel.LOW,
                    "Incluye un servicio de accesibilidad (no activo). Activalo sólo si sabés para qué lo necesita.")
            }

            // 4) Lector de notificaciones
            if (f.notificationListenerEnabled) {
                add(if (outsideStore) RiskLevel.MEDIUM else RiskLevel.LOW,
                    "Puede leer todas tus notificaciones (incluidos códigos de verificación).")
            }

            // 5) SMS
            if (hasSms && !f.isDefaultSms) {
                add(if (outsideStore) RiskLevel.HIGH else RiskLevel.MEDIUM,
                    "${verb.replaceFirstChar { it.uppercase() }} acceso a SMS sin ser tu app de mensajes predeterminada: puede leer o interceptar códigos de verificación.")
            }

            // 6) Combinación típica de troyanos bancarios
            val trojanCombo = (f.declaresAccessibility || f.accessibilityEnabled) && (hasOverlay || hasSms || hasInstall)
            if (trojanCombo && outsideStore) {
                add(RiskLevel.HIGH, "Combina accesibilidad con superposición de pantalla, SMS o instalación de apps: patrón usado por troyanos bancarios.")
            }

            // 7) Imitación de apps conocidas
            Brands.detectImitation(f.label, f.packageName)?.let {
                add(if (outsideStore || f.origin == Origin.UNKNOWN) RiskLevel.HIGH else RiskLevel.MEDIUM, it.reason)
            }

            // 8) Paquete que se hace pasar por componente del sistema
            if (f.origin != Origin.STORE &&
                (f.packageName.startsWith("com.android.") || f.packageName.startsWith("com.google.android."))
            ) {
                add(RiskLevel.MEDIUM, "Su nombre de paquete (${f.packageName}) imita al de un componente del sistema, pero no es una app del sistema.")
            }

            // 9) Sin ícono en el menú + permisos sensibles
            if (f.origin != Origin.APK_FILE && !f.hasLauncher && sensitiveCount >= 2) {
                add(RiskLevel.MEDIUM, "No muestra ícono en el menú de apps y tiene $sensitiveCount permisos sensibles: puede pasar desapercibida.")
            }

            // 10) Permisos que no parecen necesarios para el tipo de app
            unnecessaryPermissions(f, hasSms, hasCalls, hasContacts, hasMic)?.let { add(RiskLevel.MEDIUM, it) }

            // 11) Origen
            when (f.origin) {
                Origin.SIDELOADED -> {
                    if (sensitiveCount >= 3) add(RiskLevel.MEDIUM, "Instalada fuera de tiendas oficiales (${f.sourceLabel}) y con $sensitiveCount permisos sensibles concedidos.")
                    else add(RiskLevel.LOW, "Instalada fuera de tiendas oficiales (${f.sourceLabel}).")
                }
                Origin.APK_FILE -> {
                    if (sensitiveCount >= 5) add(RiskLevel.MEDIUM, "Instalador APK suelto que solicita $sensitiveCount permisos sensibles.")
                    else add(RiskLevel.LOW, "Instalador APK fuera de una tienda: instalalo sólo si conocés y confiás en el origen.")
                }
                Origin.UNKNOWN -> add(RiskLevel.LOW, "Android no informa desde dónde se instaló (ADB, preinstalada por el fabricante o restaurada).")
                else -> {
                    if (sensitiveCount >= 6) add(RiskLevel.LOW, "Tiene muchos permisos sensibles concedidos ($sensitiveCount). Revisá si los necesita.")
                }
            }

            if (hasInstall && f.origin != Origin.STORE) {
                add(RiskLevel.LOW, "Puede pedir instalar otras aplicaciones.")
            }
        }

        // Marcado como confiable por el usuario: no se oculta una amenaza confirmada.
        if (f.trusted && level != RiskLevel.CRITICAL && level != RiskLevel.SAFE) {
            reasons += "Marcada como confiable por vos: no cuenta para el nivel de riesgo."
            level = RiskLevel.SAFE
        }
        return Verdict(level, reasons)
    }

    private fun unnecessaryPermissions(f: AppFacts, sms: Boolean, calls: Boolean, contacts: Boolean, mic: Boolean): String? {
        val label = f.label.lowercase()
        val isSimpleUtility = SIMPLE_UTILITY_WORDS.any { label.contains(it) }
        val found = mutableListOf<String>()
        if (isSimpleUtility) {
            if (sms) found += "SMS"
            if (calls) found += "llamadas"
            if (contacts) found += "contactos"
            if (mic) found += "micrófono"
            if (f.declaresAccessibility) found += "accesibilidad"
            if (found.isNotEmpty()) return "Es una utilidad simple (\"${f.label}\") y aun así pide ${found.joinToString(", ")}: no parece necesario."
        }
        when (f.category) {
            ApplicationInfo.CATEGORY_GAME -> {
                if (sms) found += "SMS"
                if (calls) found += "llamadas"
                if (contacts) found += "contactos"
                if (f.declaresAccessibility) found += "accesibilidad"
                if (found.isNotEmpty()) return "Es un juego y pide ${found.joinToString(", ")}: no parece necesario para jugar."
            }
            ApplicationInfo.CATEGORY_IMAGE, ApplicationInfo.CATEGORY_VIDEO, ApplicationInfo.CATEGORY_AUDIO -> {
                if (sms) found += "SMS"
                if (calls) found += "llamadas"
                if (found.isNotEmpty()) return "Es una app multimedia y pide ${found.joinToString(", ")}: no parece necesario."
            }
        }
        return null
    }
}
