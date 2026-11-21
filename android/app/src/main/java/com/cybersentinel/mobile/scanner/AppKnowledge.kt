package com.cybersentinel.mobile.scanner

import java.text.Normalizer

/** Catálogo de permisos con explicación en lenguaje simple. */
object PermissionCatalog {

    data class Info(val label: String, val description: String, val group: String, val sensitive: Boolean = true)

    private const val P = "android.permission."

    val map: Map<String, Info> = mapOf(
        "${P}READ_SMS" to Info("Leer SMS", "Puede leer tus mensajes, incluidos los códigos de verificación de bancos y cuentas.", "SMS"),
        "${P}RECEIVE_SMS" to Info("Recibir SMS", "Puede interceptar SMS apenas llegan (por ejemplo, códigos de un solo uso).", "SMS"),
        "${P}SEND_SMS" to Info("Enviar SMS", "Puede enviar SMS, incluso a números con costo, sin que lo notes.", "SMS"),
        "${P}RECEIVE_MMS" to Info("Recibir MMS", "Puede leer mensajes multimedia entrantes.", "SMS"),
        "${P}RECEIVE_WAP_PUSH" to Info("Recibir WAP Push", "Puede recibir mensajes de configuración WAP.", "SMS"),
        "${P}READ_CALL_LOG" to Info("Leer registro de llamadas", "Puede ver a quién llamaste y quién te llamó.", "Llamadas"),
        "${P}WRITE_CALL_LOG" to Info("Modificar registro de llamadas", "Puede borrar o alterar tu historial de llamadas.", "Llamadas"),
        "${P}PROCESS_OUTGOING_CALLS" to Info("Controlar llamadas salientes", "Puede ver y redirigir las llamadas que hacés.", "Llamadas"),
        "${P}CALL_PHONE" to Info("Hacer llamadas", "Puede llamar sin pasar por el marcador.", "Llamadas"),
        "${P}ANSWER_PHONE_CALLS" to Info("Atender llamadas", "Puede atender llamadas automáticamente.", "Llamadas"),
        "${P}READ_PHONE_STATE" to Info("Estado del teléfono", "Puede conocer el estado de llamadas e identificadores de la red.", "Teléfono"),
        "${P}READ_PHONE_NUMBERS" to Info("Leer números de teléfono", "Puede leer tu número de línea.", "Teléfono"),
        "${P}READ_CONTACTS" to Info("Leer contactos", "Puede copiar tu agenda completa.", "Contactos"),
        "${P}WRITE_CONTACTS" to Info("Modificar contactos", "Puede alterar o borrar contactos.", "Contactos"),
        "${P}GET_ACCOUNTS" to Info("Ver cuentas", "Puede ver las cuentas configuradas en el teléfono.", "Contactos"),
        "${P}RECORD_AUDIO" to Info("Micrófono", "Puede grabar audio.", "Micrófono"),
        "${P}CAMERA" to Info("Cámara", "Puede sacar fotos y grabar video.", "Cámara"),
        "${P}ACCESS_FINE_LOCATION" to Info("Ubicación precisa", "Puede saber exactamente dónde estás.", "Ubicación"),
        "${P}ACCESS_COARSE_LOCATION" to Info("Ubicación aproximada", "Puede saber tu zona aproximada.", "Ubicación"),
        "${P}ACCESS_BACKGROUND_LOCATION" to Info("Ubicación en segundo plano", "Puede seguir tu ubicación aunque no la estés usando.", "Ubicación"),
        "${P}BODY_SENSORS" to Info("Sensores corporales", "Puede leer datos de sensores de salud.", "Sensores"),
        "${P}READ_CALENDAR" to Info("Leer calendario", "Puede ver tus eventos.", "Calendario"),
        "${P}WRITE_CALENDAR" to Info("Modificar calendario", "Puede crear o borrar eventos.", "Calendario"),
        "${P}READ_EXTERNAL_STORAGE" to Info("Leer almacenamiento", "Puede leer archivos del almacenamiento compartido.", "Archivos"),
        "${P}WRITE_EXTERNAL_STORAGE" to Info("Escribir almacenamiento", "Puede modificar archivos del almacenamiento compartido.", "Archivos"),
        "${P}MANAGE_EXTERNAL_STORAGE" to Info("Acceso a todos los archivos", "Puede leer y modificar todos tus archivos compartidos.", "Archivos"),
        "${P}READ_MEDIA_IMAGES" to Info("Leer fotos", "Puede ver tus fotos.", "Archivos"),
        "${P}READ_MEDIA_VIDEO" to Info("Leer videos", "Puede ver tus videos.", "Archivos"),
        "${P}SYSTEM_ALERT_WINDOW" to Info("Mostrar sobre otras apps", "Puede dibujar ventanas encima de otras apps; se usa para pantallas de login falsas.", "Superposición"),
        "${P}REQUEST_INSTALL_PACKAGES" to Info("Instalar apps", "Puede pedir instalar otras aplicaciones (fuentes desconocidas).", "Instalación"),
        "${P}REQUEST_DELETE_PACKAGES" to Info("Desinstalar apps", "Puede pedir desinstalar aplicaciones.", "Instalación", sensitive = false),
        "${P}QUERY_ALL_PACKAGES" to Info("Ver todas las apps", "Puede listar todas las aplicaciones instaladas.", "Apps", sensitive = false),
        "${P}PACKAGE_USAGE_STATS" to Info("Estadísticas de uso", "Puede saber qué apps usás y cuándo.", "Apps"),
        "${P}WRITE_SETTINGS" to Info("Modificar ajustes del sistema", "Puede cambiar ajustes del sistema.", "Sistema"),
        "${P}BIND_ACCESSIBILITY_SERVICE" to Info("Servicio de accesibilidad", "Si lo activás, puede leer todo lo que aparece en pantalla y tocar por vos.", "Accesibilidad"),
        "${P}BIND_DEVICE_ADMIN" to Info("Administración del dispositivo", "Si lo activás, puede bloquear o borrar el teléfono y dificultar su desinstalación.", "Administración"),
        "${P}BIND_NOTIFICATION_LISTENER_SERVICE" to Info("Leer notificaciones", "Si lo activás, puede leer todas tus notificaciones (incluidos códigos).", "Notificaciones"),
        "${P}BIND_VPN_SERVICE" to Info("VPN", "Si la activás, todo tu tráfico de red pasa por esta app.", "Red"),
        "${P}USE_FULL_SCREEN_INTENT" to Info("Pantalla completa", "Puede mostrar pantallas completas sobre la pantalla bloqueada.", "Superposición", sensitive = false),
        "${P}DISABLE_KEYGUARD" to Info("Desactivar bloqueo", "Puede desactivar el bloqueo de pantalla.", "Sistema"),
        "${P}RECEIVE_BOOT_COMPLETED" to Info("Iniciar con el teléfono", "Se ejecuta automáticamente al encender el teléfono.", "Sistema", sensitive = false),
        "${P}INTERNET" to Info("Internet", "Puede conectarse a Internet.", "Red", sensitive = false)
    )

    val SMS = setOf("${P}READ_SMS", "${P}RECEIVE_SMS", "${P}SEND_SMS", "${P}RECEIVE_MMS", "${P}RECEIVE_WAP_PUSH")
    val CALLS = setOf("${P}READ_CALL_LOG", "${P}WRITE_CALL_LOG", "${P}PROCESS_OUTGOING_CALLS", "${P}CALL_PHONE", "${P}ANSWER_PHONE_CALLS")
    val CONTACTS = setOf("${P}READ_CONTACTS", "${P}WRITE_CONTACTS", "${P}GET_ACCOUNTS")
    val LOCATION = setOf("${P}ACCESS_FINE_LOCATION", "${P}ACCESS_COARSE_LOCATION", "${P}ACCESS_BACKGROUND_LOCATION")
    const val MIC = "${P}RECORD_AUDIO"
    const val CAMERA = "${P}CAMERA"
    const val OVERLAY = "${P}SYSTEM_ALERT_WINDOW"
    const val INSTALL = "${P}REQUEST_INSTALL_PACKAGES"
    const val BIND_ACCESSIBILITY = "${P}BIND_ACCESSIBILITY_SERVICE"
    const val BIND_ADMIN = "${P}BIND_DEVICE_ADMIN"
    const val BIND_NOTIFICATIONS = "${P}BIND_NOTIFICATION_LISTENER_SERVICE"

    fun isSensitive(perm: String) = map[perm]?.sensitive == true
    fun label(perm: String) = map[perm]?.label ?: perm.substringAfterLast('.')
}

/** Tiendas e instaladores conocidos. */
object Installers {
    val STORES: Map<String, String> = mapOf(
        "com.android.vending" to "Google Play",
        "com.sec.android.app.samsungapps" to "Galaxy Store (Samsung)",
        "com.huawei.appmarket" to "Huawei AppGallery",
        "com.amazon.venezia" to "Amazon Appstore",
        "com.xiaomi.market" to "Xiaomi GetApps",
        "com.xiaomi.mipicks" to "Xiaomi GetApps",
        "com.heytap.market" to "OPPO App Market",
        "com.oppo.market" to "OPPO App Market",
        "com.bbk.appstore" to "vivo App Store",
        "org.fdroid.fdroid" to "F-Droid",
        "com.aurora.store" to "Aurora Store (cliente de Google Play)"
    )

    /** Instalador de paquetes del sistema: significa que el APK se instaló a mano (fuera de una tienda). */
    val PACKAGE_INSTALLERS = setOf(
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.miui.packageinstaller"
    )

    const val PLAY = "com.android.vending"
}

/** Apps populares que suelen ser imitadas, con sus paquetes oficiales. */
object Brands {
    data class Brand(val name: String, val officialPackages: Set<String>)

    val LIST = listOf(
        Brand("WhatsApp", setOf("com.whatsapp", "com.whatsapp.w4b")),
        Brand("WhatsApp Business", setOf("com.whatsapp.w4b")),
        Brand("Google Play Store", setOf("com.android.vending")),
        Brand("Play Store", setOf("com.android.vending")),
        Brand("Google Play services", setOf("com.google.android.gms")),
        Brand("Servicios de Google Play", setOf("com.google.android.gms")),
        Brand("Chrome", setOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary")),
        Brand("Google Chrome", setOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary")),
        Brand("Facebook", setOf("com.facebook.katana", "com.facebook.lite")),
        Brand("Instagram", setOf("com.instagram.android", "com.instagram.lite")),
        Brand("Messenger", setOf("com.facebook.orca", "com.facebook.mlite")),
        Brand("Telegram", setOf("org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram")),
        Brand("YouTube", setOf("com.google.android.youtube")),
        Brand("Gmail", setOf("com.google.android.gm")),
        Brand("Netflix", setOf("com.netflix.mediaclient")),
        Brand("Spotify", setOf("com.spotify.music", "com.spotify.lite")),
        Brand("TikTok", setOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill")),
        Brand("Mercado Pago", setOf("com.mercadopago.wallet")),
        Brand("Mercado Libre", setOf("com.mercadolibre")),
        Brand("Signal", setOf("org.thoughtcrime.securesms")),
        Brand("Snapchat", setOf("com.snapchat.android")),
        Brand("PayPal", setOf("com.paypal.android.p2pmobile")),
        Brand("Discord", setOf("com.discord")),
        Brand("Zoom", setOf("us.zoom.videomeetings")),
        Brand("Outlook", setOf("com.microsoft.office.outlook"))
    )

    /** Palabras que, agregadas al nombre de una marca, suelen indicar una copia o versión modificada. */
    private val SUSPICIOUS_AFFIXES = setOf(
        "update", "updater", "actualizacion", "actualizar", "plus", "gold", "mod", "premium", "pro",
        "security", "seguridad", "verificacion", "verify", "gb", "fm", "yo", "og", "fouad", "aero", "hack", "free", "gratis"
    )

    fun normalize(s: String): String {
        val noAccents = Normalizer.normalize(s.lowercase(), Normalizer.Form.NFD).replace(Regex("\\p{M}+"), "")
        val sb = StringBuilder()
        for (ch in noAccents) {
            val mapped = when (ch) {
                // Homoglifos cirílicos/griegos frecuentes
                'а' -> 'a'; 'е' -> 'e'; 'о' -> 'o'; 'р' -> 'p'; 'с' -> 'c'; 'у' -> 'y'; 'х' -> 'x'; 'і' -> 'i'; 'ѕ' -> 's'
                'α' -> 'a'; 'ο' -> 'o'; 'ρ' -> 'p'; 'ν' -> 'v'; 'τ' -> 't'
                // Dígitos usados como letras
                '0' -> 'o'; '1' -> 'l'; '3' -> 'e'; '5' -> 's'; '@' -> 'a'; '$' -> 's'
                else -> ch
            }
            if (mapped.isLetterOrDigit()) sb.append(mapped)
        }
        return sb.toString().replace("rn", "m").replace("vv", "w")
    }

    data class Imitation(val brand: Brand, val reason: String)

    /** Devuelve la marca imitada si el nombre se parece a una app conocida pero el paquete no es oficial. */
    fun detectImitation(label: String, packageName: String): Imitation? {
        val n = normalize(label)
        if (n.length < 3) return null
        for (b in LIST) {
            if (packageName in b.officialPackages) continue
            val bn = normalize(b.name)
            if (n == bn) {
                return Imitation(b, "Usa el mismo nombre que \"${b.name}\" pero su paquete ($packageName) no es el oficial.")
            }
            if (bn.length >= 6 && levenshtein(n, bn) == 1) {
                return Imitation(b, "Su nombre \"$label\" es casi idéntico a \"${b.name}\" (una letra de diferencia) y no es la app oficial.")
            }
            if (n.contains(bn) && n != bn) {
                val rest = n.replace(bn, "")
                if (rest in SUSPICIOUS_AFFIXES) {
                    return Imitation(b, "Su nombre combina \"${b.name}\" con \"$rest\", patrón típico de copias o versiones modificadas no oficiales.")
                }
            }
        }
        return null
    }

    fun levenshtein(a: String, b: String): Int {
        if (a == b) return 0
        if (kotlin.math.abs(a.length - b.length) > 2) return 99
        var prev = IntArray(b.length + 1) { it }
        var cur = IntArray(b.length + 1)
        for (i in 1..a.length) {
            cur[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = minOf(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            }
            val t = prev; prev = cur; cur = t
        }
        return prev[b.length]
    }
}
