package com.cybersentinel.mobile.scanner

import android.content.Context
import android.os.Environment
import android.os.SystemClock
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.ScanRecord
import com.cybersentinel.mobile.data.ScanStatus
import com.cybersentinel.mobile.data.ScanType
import com.cybersentinel.mobile.util.Format
import com.cybersentinel.mobile.util.Prefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.NonCancellable
import java.io.File
import java.io.IOException
import java.util.concurrent.CancellationException
import kotlin.coroutines.coroutineContext

data class ScanProgress(
    val running: Boolean = false,
    val type: ScanType? = null,
    val phase: String = "",
    val current: Int = 0,
    val total: Int = 0,
    val currentItem: String = "",
    val filesScanned: Int = 0,
    val appsScanned: Int = 0,
    val confirmed: Int = 0,
    val suspicious: Int = 0,
    val scanId: Long? = null,
    val lastFinishedScanId: Long? = null,
    val lastResult: String? = null,
    val startedAt: Long = 0
) {
    /** Progreso real 0..1, o null si la fase aún no conoce el total (se muestra indeterminado). */
    val fraction: Float? get() = if (total > 0) (current.toFloat() / total).coerceIn(0f, 1f) else null
}

/**
 * Orquesta los análisis. Corre en segundo plano dentro del proceso de la app; el progreso se
 * publica en [progress] para la interfaz. Cada análisis se guarda en SQLite con sus hallazgos.
 */
object ScanManager {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _progress = MutableStateFlow(ScanProgress())
    val progress: StateFlow<ScanProgress> = _progress.asStateFlow()
    private var job: Job? = null

    /** Se incrementa cada vez que cambian datos persistidos (para que la UI recargue). */
    private val _dataVersion = MutableStateFlow(0)
    val dataVersion: StateFlow<Int> = _dataVersion.asStateFlow()
    fun notifyDataChanged() { _dataVersion.value = _dataVersion.value + 1 }

    @Synchronized
    fun start(context: Context, type: ScanType): Boolean {
        if (job?.isActive == true) return false
        val app = context.applicationContext
        _progress.value = ScanProgress(running = true, type = type, phase = "Preparando…", startedAt = System.currentTimeMillis())
        job = scope.launch { ScanEngine(app).run(type, _progress) }
        job?.invokeOnCompletion { notifyDataChanged() }
        return true
    }

    fun cancel() { job?.cancel() }
}

private class Candidate(val node: ScanNode, val hiddenAncestorId: String?)

private class HiddenDir(val node: ScanNode, var files: Int = 0)

class ScanEngine(private val context: Context) {

    private val db = Database.get(context)
    private val prefs = Prefs(context)
    private val apps = AppScanner(context, db)

    private val knownBenignHidden = setOf(
        ".thumbnails", ".nomedia", ".trash", ".trashes", ".recycle", ".pending", ".database_uuid", ".estrongs", ".face", ".cache"
    )

    suspend fun run(type: ScanType, progress: MutableStateFlow<ScanProgress>) {
        val started = System.currentTimeMillis()
        val scanId = db.insertScan(ScanRecord(type = type, startedAt = started))
        db.log("Análisis iniciado", "${type.label} (#$scanId)")
        progress.value = progress.value.copy(scanId = scanId)

        val findings = ArrayList<Finding>()
        var record = ScanRecord(id = scanId, type = type, startedAt = started)
        val notes = mutableListOf<String>()
        var errors = 0
        var filesScanned = 0
        var filesHashed = 0
        var hiddenCount = 0
        var appsScanned = 0
        var status = ScanStatus.COMPLETED
        val locations = mutableListOf<String>()

        var lastEmit = 0L
        fun emit(force: Boolean = false, update: (ScanProgress) -> ScanProgress) {
            val now = SystemClock.elapsedRealtime()
            if (force || now - lastEmit > 120) {
                lastEmit = now
                progress.value = update(progress.value)
            }
        }
        fun countRisk() = findings.count { it.level == RiskLevel.CRITICAL } to findings.count { it.level.weight in 1..3 }

        try {
            // ------------------------------------------------------------------ ARCHIVOS
            if (type != ScanType.APPS) {
                val roots = collectRoots(type, locations, notes)
                val candidates = ArrayList<Candidate>()
                val hiddenDirs = LinkedHashMap<String, HiddenDir>()

                emit(true) { it.copy(phase = "Buscando archivos…", current = 0, total = 0) }
                for ((root, maxDepth) in roots) {
                    walk(root, maxDepth, candidates, hiddenDirs) { count, path ->
                        emit { it.copy(currentItem = path, filesScanned = count) }
                    }
                }

                val hashLimit = prefs.maxHashMb.toLong() * 1024 * 1024
                val groups = HashMap<String, MutableList<Pair<Int, Candidate>>>() // sha -> (índice de hallazgo o -1, candidato)
                val findingIndexByNode = HashMap<String, Int>()
                val realTypes = HashMap<String, RealType>()

                candidates.forEachIndexed { i, cand ->
                    coroutineContext.ensureActive()
                    val node = cand.node
                    emit { it.copy(phase = "Analizando archivos…", current = i, total = candidates.size, currentItem = node.displayPath, filesScanned = i) }
                    cand.hiddenAncestorId?.let { hiddenDirs[it]?.let { h -> h.files++ } }

                    val result = analyzeFile(node, hashLimit)
                    filesScanned++
                    if (result.readError != null) errors++
                    if (result.sha != null) filesHashed++
                    realTypes[node.id] = result.realType

                    val store = result.verdict.level != RiskLevel.SAFE || node.isHiddenName
                    if (store) {
                        if (node.isHiddenName) hiddenCount++
                        findingIndexByNode[node.id] = findings.size
                        findings += fileFinding(scanId, node, result, isHidden = node.isHiddenName)
                    }
                    result.sha?.let { sha -> groups.getOrPut(sha) { mutableListOf() }.add((findingIndexByNode[node.id] ?: -1) to cand) }
                    val (c, s) = countRisk()
                    emit { it.copy(confirmed = c, suspicious = s) }
                }
                emit(true) { it.copy(current = candidates.size, total = candidates.size, filesScanned = candidates.size) }

                // Carpetas ocultas
                for (h in hiddenDirs.values) {
                    hiddenCount++
                    val reasons = mutableListOf("Carpeta oculta (su nombre empieza con punto) con ${h.files} archivo(s) analizado(s).")
                    if (h.node.name.lowercase() in knownBenignHidden || h.node.name.lowercase().startsWith(".trashed") || h.node.name.lowercase().startsWith(".pending"))
                        reasons += "Es una carpeta habitual de Android o de apps (caché, papelera o miniaturas)."
                    findings += Finding(
                        scanId = scanId, kind = FindingKind.FILE, level = RiskLevel.SAFE, title = "Carpeta oculta",
                        name = h.node.name, location = h.node.displayPath.substringBeforeLast('/'), uri = h.node.id,
                        storageKind = h.node.storageKind, modifiedAt = h.node.lastModified, createdAt = h.node.createdAt(),
                        reasons = reasons, isHidden = true, isDirectory = true
                    )
                }

                // Duplicados sospechosos
                emit(true) { it.copy(phase = "Buscando duplicados sospechosos…", current = 0, total = 0, currentItem = "") }
                for ((sha, members) in groups) {
                    if (members.size < 2) continue
                    val names = members.map { it.second.node.name }
                    val exts = names.map { FileTypes.extensionOf(it) }.toSet()
                    val anyExec = members.any { realTypes[it.second.node.id]?.executable == true }
                    val distinctNames = names.map { it.lowercase() }.toSet().size > 1
                    val level = when {
                        anyExec && distinctNames -> RiskLevel.MEDIUM
                        exts.size > 1 -> RiskLevel.LOW
                        else -> continue
                    }
                    val title = if (anyExec) "Ejecutable duplicado con otro nombre" else "Mismo contenido con distinta extensión"
                    for ((idx, cand) in members) {
                        val others = members.filter { it.second !== cand }.take(4).joinToString("; ") { it.second.node.displayPath }
                        val reason = "[${level.label}] Mismo contenido (SHA-256 ${sha.take(12)}…) que: $others"
                        if (idx >= 0) {
                            val f = findings[idx]
                            findings[idx] = f.copy(
                                reasons = f.reasons + reason,
                                level = RiskLevel.max(f.level, level),
                                title = if (level.weight > f.level.weight) title else f.title
                            )
                        } else {
                            val node = cand.node
                            findings += Finding(
                                scanId = scanId, kind = FindingKind.FILE, level = level, title = title,
                                name = node.name, location = node.displayPath.substringBeforeLast('/'), uri = node.id,
                                storageKind = node.storageKind, parentUri = node.parentId, size = node.size, createdAt = node.createdAt(),
                                modifiedAt = node.lastModified, sha256 = sha, realType = realTypes[node.id]?.label,
                                reasons = listOf(reason)
                            )
                        }
                    }
                }
            }

            // ------------------------------------------------------------- APLICACIONES
            coroutineContext.ensureActive()
            emit(true) { it.copy(phase = "Analizando aplicaciones…", current = 0, total = 0, currentItem = "") }
            apps.prepare()
            val packages = apps.listPackages(prefs.includeSystemApps)
            val hashLimit = prefs.maxHashMb.toLong() * 1024 * 1024
            val appCtx = coroutineContext
            val isCancelled = { !appCtx.isActive }
            packages.forEachIndexed { i, pkg ->
                coroutineContext.ensureActive()
                emit { it.copy(phase = "Analizando aplicaciones…", current = i, total = packages.size, currentItem = pkg, appsScanned = i) }
                val res = runCatching { apps.inspect(pkg, hashLimit, isCancelled) }.getOrElse { e ->
                    if (e is CancellationException) throw e
                    errors++; null
                } ?: return@forEachIndexed
                appsScanned++
                val (facts, verdict) = res
                findings += Finding(
                    scanId = scanId, kind = FindingKind.APP, level = verdict.level,
                    title = facts.label, name = facts.label, location = facts.sourceLabel,
                    uri = facts.apkPath, size = facts.apkSize, createdAt = facts.firstInstall, modifiedAt = facts.lastUpdate,
                    sha256 = facts.sha256, realType = facts.origin.name, packageName = facts.packageName,
                    reasons = buildAppReasons(facts, verdict)
                )
                val (c, s) = countRisk()
                emit { it.copy(confirmed = c, suspicious = s) }
            }
            emit(true) { it.copy(current = packages.size, total = packages.size, appsScanned = appsScanned) }

            // --------------------------------------------------------- DISPOSITIVO
            emit(true) { it.copy(phase = "Revisando configuración del dispositivo…", current = 0, total = 0, currentItem = "") }
            findings += DeviceAuditor.audit(context, scanId)
        } catch (e: CancellationException) {
            status = ScanStatus.CANCELLED
            notes += "Análisis cancelado por el usuario: los resultados son parciales."
        } catch (e: Exception) {
            status = ScanStatus.FAILED
            notes += "Error durante el análisis: ${e.javaClass.simpleName}: ${e.message}"
        } finally {
            withContext(NonCancellable) {
                progress.value = progress.value.copy(phase = "Guardando resultados…", currentItem = "")
                db.insertFindings(findings)
                val risky = findings.filter { it.level != RiskLevel.SAFE }
                val overall = risky.maxByOrNull { it.level.weight }?.level ?: RiskLevel.SAFE
                if (errors > 0) notes += "$errors elemento(s) no se pudieron leer por completo."
                record = record.copy(
                    finishedAt = System.currentTimeMillis(),
                    status = status,
                    filesScanned = filesScanned,
                    filesHashed = filesHashed,
                    hiddenCount = hiddenCount,
                    appsScanned = appsScanned,
                    critical = risky.count { it.level == RiskLevel.CRITICAL },
                    high = risky.count { it.level == RiskLevel.HIGH },
                    medium = risky.count { it.level == RiskLevel.MEDIUM },
                    low = risky.count { it.level == RiskLevel.LOW },
                    errors = errors,
                    locations = locations.joinToString("\n"),
                    overallLevel = overall,
                    notes = notes.joinToString("\n")
                )
                db.updateScan(record)
                val duration = Format.duration(record.finishedAt!! - started)
                db.log(
                    "Análisis ${if (status == ScanStatus.COMPLETED) "finalizado" else status.name.lowercase()}",
                    "${type.label} (#$scanId): $filesScanned archivos, $appsScanned apps, ${record.critical} confirmadas, " +
                        "${record.high + record.medium + record.low} sospechosos, $duration"
                )
                progress.value = ScanProgress(
                    running = false,
                    lastFinishedScanId = scanId,
                    lastResult = when (status) {
                        ScanStatus.COMPLETED -> "Análisis terminado en $duration"
                        ScanStatus.CANCELLED -> "Análisis cancelado (resultados parciales guardados)"
                        else -> "El análisis terminó con errores"
                    }
                )
            }
        }
    }

    // ---------------------------------------------------------------------- raíces

    private fun collectRoots(type: ScanType, locations: MutableList<String>, notes: MutableList<String>): List<Pair<ScanNode, Int>> {
        val roots = mutableListOf<Pair<ScanNode, Int>>()
        val allFiles = StorageAccess.hasAllFilesAccess(context)
        val quick = type == ScanType.QUICK
        if (allFiles) {
            val base = Environment.getExternalStorageDirectory()
            val rootName = "Almacenamiento interno"
            if (quick) {
                // Rápido: ubicaciones donde suelen llegar archivos de terceros.
                val dirs = listOf(
                    Environment.DIRECTORY_DOWNLOADS to 4,
                    Environment.DIRECTORY_DOCUMENTS to 3,
                    "Bluetooth" to 2
                )
                for ((d, depth) in dirs) {
                    val f = File(base, d)
                    if (f.isDirectory) {
                        roots += ScanNode.FileNode(f, "$rootName/$d") to depth
                        locations += "$rootName/$d"
                    }
                }
                roots += ScanNode.FileNode(base, rootName) to 0
                locations += "$rootName (sólo archivos de la raíz)"
            } else {
                roots += ScanNode.FileNode(base, rootName) to 40
                locations += "$rootName (completo)"
            }
        }
        for (folder in StorageAccess.safFolders(context)) {
            if (allFiles && StorageAccess.isPrimaryTree(folder.treeUri)) continue
            val node = ScanNode.SafNode.root(context, folder.treeUri)
            if (node == null) {
                notes += "No se pudo abrir la carpeta autorizada ${folder.displayName} (¿se quitó la tarjeta o se revocó el permiso?)."
                continue
            }
            roots += node to (if (quick) 3 else 40)
            locations += folder.displayName
        }
        if (roots.isEmpty()) {
            notes += "No hay carpetas con acceso concedido: sólo se analizaron aplicaciones y configuración. Agregá carpetas o activá el acceso a archivos en Ajustes."
        }
        return roots
    }

    /**
     * Recorre el árbol de carpetas. [maxDepth] = 0 significa sólo los archivos directos de la raíz.
     * Se omiten Android/data y Android/obb (protegidas por Android y privadas de otras apps).
     */
    private suspend fun walk(
        root: ScanNode,
        maxDepth: Int,
        out: MutableList<Candidate>,
        hiddenDirs: MutableMap<String, HiddenDir>,
        onProgress: (Int, String) -> Unit
    ) {
        data class Item(val node: ScanNode, val depth: Int, val hiddenAncestor: String?)
        val stack = ArrayDeque<Item>()
        stack.addLast(Item(root, 0, null))
        val seen = HashSet<String>()
        while (stack.isNotEmpty()) {
            coroutineContext.ensureActive()
            val (dir, depth, hiddenAncestor) = stack.removeLast()
            if (!seen.add(dir.id)) continue
            val children = try { dir.children(context) } catch (e: Exception) { emptyList() }
            for (child in children) {
                if (child.isDirectory) {
                    if (isProtectedAppDir(child)) continue
                    if (depth + 1 > maxDepth) continue
                    var hidden = hiddenAncestor
                    if (child.isHiddenName && !hiddenDirs.containsKey(child.id)) {
                        hiddenDirs[child.id] = HiddenDir(child)
                        hidden = child.id
                    }
                    stack.addLast(Item(child, depth + 1, hidden))
                } else {
                    // Un archivo que ya fue listado desde otra raíz no se analiza dos veces.
                    if (out.size < 1_000_000) out += Candidate(child, hiddenAncestor)
                }
            }
            onProgress(out.size, dir.displayPath)
        }
    }

    private fun isProtectedAppDir(node: ScanNode): Boolean {
        val p = node.displayPath.lowercase()
        return p.endsWith("/android/data") || p.endsWith("/android/obb") || p.endsWith("/android/media/.thumbnails-private")
    }

    // ------------------------------------------------------------------- archivos

    private class FileResult(
        val verdict: FileVerdict,
        val realType: RealType,
        val sha: String?,
        val readError: String?,
        val hashSkipped: Boolean
    )

    private suspend fun analyzeFile(node: ScanNode, hashLimit: Long): FileResult {
        val ctxJob = coroutineContext
        val isCancelled = { !ctxJob.isActive }
        var content: ContentReport? = null
        var readError: String? = null
        try {
            content = ContentReader.read({ node.open(context) }, node.size, hashLimit, isCancelled)
        } catch (e: CancellationException) {
            throw e
        } catch (e: SecurityException) {
            readError = "sin permiso de lectura"
        } catch (e: IOException) {
            readError = e.message ?: "error de lectura"
        } catch (e: Exception) {
            readError = e.javaClass.simpleName
        }

        var realType = content?.realType ?: RealType.UNKNOWN
        var zip: ZipInfo? = null
        if (realType == RealType.ZIP) {
            zip = when (node) {
                is ScanNode.FileNode -> ZipInspector.inspectFile(node.file)
                is ScanNode.SafNode -> if (node.size <= 300L * 1024 * 1024)
                    runCatching { ZipInspector.inspectStream(node.open(context), isCancelled) }.getOrNull() else null
            }
            zip?.let { realType = it.refinedType }
        }

        val sha = content?.sha256
        val signature = sha?.let { db.findSignature(it) }

        var apkVerdict: Pair<AppFacts, Verdict>? = null
        if (realType == RealType.APK && node.size <= 200L * 1024 * 1024) {
            apkVerdict = when (node) {
                is ScanNode.FileNode -> runCatching { apps.inspectApkFile(node.file, sha) }.getOrNull()
                is ScanNode.SafNode -> {
                    val tmp = File(context.cacheDir, "apk_inspect_${System.nanoTime()}.apk")
                    try {
                        node.open(context).use { input -> tmp.outputStream().use { input.copyTo(it) } }
                        runCatching { apps.inspectApkFile(tmp, sha) }.getOrNull()
                    } catch (e: Exception) {
                        null
                    } finally {
                        tmp.delete()
                    }
                }
            }
        }

        val trusted = sha?.let { db.isTrusted("hash:$it") } ?: false
        val ctx = FileContext(
            name = node.name, displayPath = node.displayPath, size = node.size, content = content,
            realType = realType, zip = zip, apkVerdict = apkVerdict, signature = signature,
            trusted = trusted, readError = readError
        )
        var verdict = FileRules.evaluate(ctx)
        val hashSkipped = sha == null && readError == null && node.size > hashLimit
        if (hashSkipped && verdict.level != RiskLevel.SAFE) {
            verdict = verdict.copy(reasons = verdict.reasons + "SHA-256 no calculado: el archivo supera el límite configurado (${Format.size(hashLimit)}).")
        }
        return FileResult(verdict, realType, sha, readError, hashSkipped)
    }

    private fun fileFinding(scanId: Long, node: ScanNode, r: FileResult, isHidden: Boolean): Finding {
        val reasons = r.verdict.reasons.toMutableList()
        if (isHidden) reasons.add(0, "Archivo oculto: su nombre empieza con punto, por eso no aparece en la mayoría de los exploradores.")
        return Finding(
            scanId = scanId,
            kind = FindingKind.FILE,
            level = r.verdict.level,
            title = r.verdict.title,
            name = node.name,
            location = node.displayPath.substringBeforeLast('/'),
            uri = node.id,
            storageKind = node.storageKind,
            parentUri = node.parentId,
            size = node.size,
            createdAt = node.createdAt(),
            modifiedAt = node.lastModified,
            sha256 = r.sha,
            realType = r.realType.label,
            reasons = reasons,
            isHidden = isHidden
        )
    }

    private fun buildAppReasons(f: AppFacts, v: Verdict): List<String> {
        val out = v.reasons.toMutableList()
        out += "Origen: ${f.sourceLabel}"
        f.versionName?.let { out += "Versión: $it" }
        val sensitiveGranted = f.granted.filter { PermissionCatalog.isSensitive(it) }
        out += if (sensitiveGranted.isEmpty()) "Permisos sensibles concedidos: ninguno"
        else "Permisos sensibles concedidos: " + sensitiveGranted.joinToString(", ") { PermissionCatalog.label(it) }
        if (f.adminActive) out += "Estado: administrador del dispositivo ACTIVO"
        if (f.accessibilityEnabled) out += "Estado: servicio de accesibilidad ACTIVO"
        if (f.notificationListenerEnabled) out += "Estado: acceso a notificaciones ACTIVO"
        if (!f.hasLauncher) out += "No tiene ícono en el menú de aplicaciones"
        if (f.sha256 == null && f.origin != Origin.SYSTEM) out += "SHA-256 del APK: no calculado (tamaño o lectura)"
        return out
    }
}
