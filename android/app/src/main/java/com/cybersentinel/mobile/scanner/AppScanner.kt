package com.cybersentinel.mobile.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat
import com.cybersentinel.mobile.data.Database
import java.io.File

/** Lee la información REAL que Android expone sobre las apps instaladas (PackageManager y servicios del sistema). */
class AppScanner(private val context: Context, private val db: Database) {

    private val pm: PackageManager = context.packageManager

    /** Estado global del sistema, consultado una sola vez por análisis. */
    private class SystemState(
        val enabledAccessibility: Set<String>,
        val declaredAccessibility: Set<String>,
        val activeAdmins: Set<String>,
        val declaredAdmins: Set<String>,
        val declaredListeners: Set<String>,
        val enabledListeners: Set<String>,
        val launcherPackages: Set<String>,
        val defaultSms: String?
    )

    @Suppress("DEPRECATION")
    private fun loadSystemState(): SystemState {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledA11y = runCatching {
            am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }.toSet()
        }.getOrDefault(emptySet())
        val declaredA11y = runCatching {
            am.installedAccessibilityServiceList.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }.toSet()
        }.getOrDefault(emptySet())

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val activeAdmins = runCatching { dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet() }.getOrDefault(emptySet())
        val declaredAdmins = runCatching {
            pm.queryBroadcastReceivers(Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_ENABLED), 0)
                .mapNotNull { it.activityInfo?.packageName }.toSet()
        }.getOrDefault(emptySet())

        val declaredListeners = runCatching {
            pm.queryIntentServices(Intent(NotificationListenerService.SERVICE_INTERFACE), 0)
                .mapNotNull { it.serviceInfo?.packageName }.toSet()
        }.getOrDefault(emptySet())
        val enabledListeners = runCatching { NotificationManagerCompat.getEnabledListenerPackages(context) }.getOrDefault(emptySet())

        val launcher = runCatching {
            pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
                .mapNotNull { it.activityInfo?.packageName }.toSet()
        }.getOrDefault(emptySet())

        val defaultSms = runCatching { Telephony.Sms.getDefaultSmsPackage(context) }.getOrNull()

        return SystemState(enabledA11y, declaredA11y, activeAdmins, declaredAdmins, declaredListeners, enabledListeners, launcher, defaultSms)
    }

    @Suppress("DEPRECATION")
    fun listPackages(includeSystem: Boolean): List<String> {
        val all: List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
        } else {
            pm.getInstalledPackages(0)
        }
        return all.filter { p ->
            val ai = p.applicationInfo ?: return@filter false
            p.packageName != context.packageName &&
                (includeSystem || (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0 || (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)
        }.map { it.packageName }
    }

    private var state: SystemState? = null

    fun prepare() { state = loadSystemState() }

    /**
     * Reúne los datos de una app y la evalúa.
     * @param hashLimitBytes tamaño máximo del APK para calcular SHA-256.
     */
    @Suppress("DEPRECATION")
    fun inspect(packageName: String, hashLimitBytes: Long, isCancelled: () -> Boolean): Pair<AppFacts, Verdict>? {
        val s = state ?: loadSystemState().also { state = it }
        val info: PackageInfo = runCatching {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            else pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
        }.getOrNull() ?: return null
        val ai = info.applicationInfo ?: return null

        val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(packageName)

        // Origen de instalación
        var installer: String? = null
        var initiating: String? = null
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val src = pm.getInstallSourceInfo(packageName)
                installer = src.installingPackageName
                initiating = src.initiatingPackageName
            } else {
                installer = pm.getInstallerPackageName(packageName)
            }
        }
        val (origin, sourceLabel) = classifyOrigin(isSystem, installer, initiating)

        // Permisos solicitados y concedidos
        val requested = info.requestedPermissions?.toList() ?: emptyList()
        val flags = info.requestedPermissionsFlags
        val granted = HashSet<String>()
        requested.forEachIndexed { i, perm ->
            if (flags != null && i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) granted.add(perm)
        }

        // Hash del APK base (legible por cualquier app) para comparar con la base de firmas
        var sha: String? = null
        var apkSize: Long? = null
        val apkPath = ai.sourceDir
        if (apkPath != null && !isSystem) {
            val f = File(apkPath)
            apkSize = f.length().takeIf { it > 0 }
            if (f.canRead() && f.length() in 1..hashLimitBytes && !isCancelled()) {
                sha = runCatching { Hashing.sha256(f.inputStream(), isCancelled) }.getOrNull()
            }
        }
        val match = sha?.let { db.findSignature(it) }

        val facts = AppFacts(
            packageName = packageName,
            label = label,
            versionName = info.versionName,
            origin = origin,
            sourceLabel = sourceLabel,
            requested = requested,
            granted = granted,
            declaresAccessibility = packageName in s.declaredAccessibility,
            accessibilityEnabled = packageName in s.enabledAccessibility,
            declaresAdmin = packageName in s.declaredAdmins,
            adminActive = packageName in s.activeAdmins,
            declaresNotificationListener = packageName in s.declaredListeners,
            notificationListenerEnabled = packageName in s.enabledListeners,
            isDefaultSms = packageName == s.defaultSms,
            hasLauncher = packageName in s.launcherPackages,
            category = ai.category,
            firstInstall = info.firstInstallTime.takeIf { it > 0 },
            lastUpdate = info.lastUpdateTime.takeIf { it > 0 },
            apkPath = apkPath,
            apkSize = apkSize,
            sha256 = sha,
            signatureMatch = match,
            trusted = db.isTrusted("app:$packageName")
        )
        return facts to AppRules.evaluate(facts)
    }

    private fun classifyOrigin(isSystem: Boolean, installer: String?, initiating: String?): Pair<Origin, String> {
        if (isSystem) return Origin.SYSTEM to "Sistema / fabricante"
        if (installer != null && installer in Installers.STORES) return Origin.STORE to Installers.STORES.getValue(installer)
        if (installer != null && installer in Installers.PACKAGE_INSTALLERS) {
            val by = initiating?.takeIf { it !in Installers.PACKAGE_INSTALLERS }?.let { appLabel(it) }
            return Origin.SIDELOADED to (if (by != null) "APK instalado manualmente desde $by" else "APK instalado manualmente")
        }
        if (installer != null) return Origin.SIDELOADED to "Instalada por ${appLabel(installer)}"
        return Origin.UNKNOWN to "No informado"
    }

    @Suppress("DEPRECATION")
    fun appLabel(pkg: String): String = runCatching {
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    }.getOrDefault(pkg)

    /** Analiza un archivo APK NO instalado (sólo lectura, sin instalarlo). */
    @Suppress("DEPRECATION")
    fun inspectApkFile(apk: File, sha: String?): Pair<AppFacts, Verdict>? {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        val info = runCatching {
            if (Build.VERSION.SDK_INT >= 33)
                pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            else pm.getPackageArchiveInfo(apk.absolutePath, flags)
        }.getOrNull() ?: return null
        val ai = info.applicationInfo
        var label = info.packageName
        if (ai != null) {
            ai.sourceDir = apk.absolutePath
            ai.publicSourceDir = apk.absolutePath
            label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(info.packageName)
        }
        val requested = info.requestedPermissions?.toList() ?: emptyList()
        // Componentes protegidos por permisos de sistema = servicios de accesibilidad / receptores de administración
        val declaresA11y = info.services?.any { it.permission == PermissionCatalog.BIND_ACCESSIBILITY } == true
        val declaresListener = info.services?.any { it.permission == PermissionCatalog.BIND_NOTIFICATIONS } == true
        val declaresAdmin = info.receivers?.any { it.permission == PermissionCatalog.BIND_ADMIN } == true
        val facts = AppFacts(
            packageName = info.packageName,
            label = label,
            versionName = info.versionName,
            origin = Origin.APK_FILE,
            sourceLabel = "Archivo APK",
            requested = requested,
            granted = emptySet(),
            declaresAccessibility = declaresA11y,
            declaresAdmin = declaresAdmin,
            declaresNotificationListener = declaresListener,
            category = ai?.category ?: ApplicationInfo.CATEGORY_UNDEFINED,
            sha256 = sha,
            signatureMatch = sha?.let { db.findSignature(it) }
        )
        return facts to AppRules.evaluate(facts)
    }
}
