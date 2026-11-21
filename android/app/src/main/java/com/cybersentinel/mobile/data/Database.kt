package com.cybersentinel.mobile.data

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Base de datos local (SQLite) para historial, hallazgos, firmas, cuarentena y registro de acciones.
 * Todo queda en el almacenamiento interno de la app; nada se sincroniza ni se respalda.
 */
class Database private constructor(context: Context) :
    SQLiteOpenHelper(context.applicationContext, DB_NAME, null, DB_VERSION) {

    companion object {
        private const val DB_NAME = "cybersentinel.db"
        private const val DB_VERSION = 1

        @Volatile private var instance: Database? = null
        fun get(context: Context): Database =
            instance ?: synchronized(this) {
                instance ?: Database(context).also { instance = it }
            }

        /** SHA-256 del archivo de prueba estándar EICAR (inofensivo, usado por todos los antivirus para pruebas). */
        const val EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    }

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                status TEXT NOT NULL,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                files_hashed INTEGER NOT NULL DEFAULT 0,
                hidden_count INTEGER NOT NULL DEFAULT 0,
                apps_scanned INTEGER NOT NULL DEFAULT 0,
                critical INTEGER NOT NULL DEFAULT 0,
                high INTEGER NOT NULL DEFAULT 0,
                medium INTEGER NOT NULL DEFAULT 0,
                low INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                locations TEXT NOT NULL DEFAULT '',
                overall_level TEXT NOT NULL DEFAULT 'SAFE',
                notes TEXT NOT NULL DEFAULT ''
            )"""
        )
        db.execSQL(
            """CREATE TABLE findings(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                level TEXT NOT NULL,
                title TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT NOT NULL,
                uri TEXT,
                storage_kind TEXT,
                parent_uri TEXT,
                size INTEGER,
                created_at INTEGER,
                modified_at INTEGER,
                sha256 TEXT,
                real_type TEXT,
                package_name TEXT,
                reasons TEXT NOT NULL DEFAULT '',
                is_hidden INTEGER NOT NULL DEFAULT 0,
                is_directory INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'OPEN'
            )"""
        )
        db.execSQL("CREATE INDEX idx_findings_scan ON findings(scan_id)")
        db.execSQL(
            """CREATE TABLE signatures(
                sha256 TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                added_at INTEGER NOT NULL
            ) WITHOUT ROWID"""
        )
        db.execSQL(
            """CREATE TABLE trusted(
                key TEXT PRIMARY KEY,
                added_at INTEGER NOT NULL
            ) WITHOUT ROWID"""
        )
        db.execSQL(
            """CREATE TABLE quarantine(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                original_location TEXT NOT NULL,
                original_uri TEXT NOT NULL,
                parent_uri TEXT NOT NULL,
                storage_kind TEXT NOT NULL,
                mime TEXT,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                quarantined_at INTEGER NOT NULL,
                stored_file TEXT NOT NULL,
                reason TEXT NOT NULL,
                finding_id INTEGER
            )"""
        )
        db.execSQL(
            """CREATE TABLE action_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            )"""
        )
        // Única firma incluida de fábrica: el archivo de prueba EICAR (no es malware real).
        // Las firmas reales se importan desde Ajustes (por ejemplo, exportaciones de MalwareBazaar).
        db.insert("signatures", null, ContentValues().apply {
            put("sha256", EICAR_SHA256)
            put("name", "EICAR-Test-File (archivo de prueba estándar)")
            put("source", "Incluida")
            put("added_at", System.currentTimeMillis())
        })
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Versión 1: sin migraciones todavía.
    }

    // ---------------------------------------------------------------- scans

    fun insertScan(s: ScanRecord): Long = writableDatabase.insert("scans", null, scanValues(s))

    fun updateScan(s: ScanRecord) {
        writableDatabase.update("scans", scanValues(s), "id=?", arrayOf(s.id.toString()))
    }

    private fun scanValues(s: ScanRecord) = ContentValues().apply {
        put("type", s.type.name)
        put("started_at", s.startedAt)
        put("finished_at", s.finishedAt)
        put("status", s.status.name)
        put("files_scanned", s.filesScanned)
        put("files_hashed", s.filesHashed)
        put("hidden_count", s.hiddenCount)
        put("apps_scanned", s.appsScanned)
        put("critical", s.critical)
        put("high", s.high)
        put("medium", s.medium)
        put("low", s.low)
        put("errors", s.errors)
        put("locations", s.locations)
        put("overall_level", s.overallLevel.name)
        put("notes", s.notes)
    }

    fun getScans(limit: Int = 200): List<ScanRecord> =
        readableDatabase.query("scans", null, null, null, null, null, "started_at DESC", limit.toString())
            .use { c -> buildList { while (c.moveToNext()) add(c.toScan()) } }

    fun getScan(id: Long): ScanRecord? =
        readableDatabase.query("scans", null, "id=?", arrayOf(id.toString()), null, null, null)
            .use { c -> if (c.moveToFirst()) c.toScan() else null }

    /** Último análisis terminado. Si [types] no está vacío, filtra por esos tipos. */
    fun latestCompletedScan(vararg types: ScanType): ScanRecord? {
        val where = StringBuilder("status='COMPLETED'")
        val args = mutableListOf<String>()
        if (types.isNotEmpty()) {
            where.append(" AND type IN (").append(types.joinToString(",") { "?" }).append(")")
            types.forEach { args.add(it.name) }
        }
        return readableDatabase.query("scans", null, where.toString(), args.toTypedArray(), null, null, "started_at DESC", "1")
            .use { c -> if (c.moveToFirst()) c.toScan() else null }
    }

    fun deleteScan(id: Long) {
        writableDatabase.delete("scans", "id=?", arrayOf(id.toString()))
    }

    private fun Cursor.toScan() = ScanRecord(
        id = long("id"),
        type = ScanType.fromName(str("type")),
        startedAt = long("started_at"),
        finishedAt = longOrNull("finished_at"),
        status = ScanStatus.fromName(str("status")),
        filesScanned = int("files_scanned"),
        filesHashed = int("files_hashed"),
        hiddenCount = int("hidden_count"),
        appsScanned = int("apps_scanned"),
        critical = int("critical"),
        high = int("high"),
        medium = int("medium"),
        low = int("low"),
        errors = int("errors"),
        locations = str("locations") ?: "",
        overallLevel = RiskLevel.fromName(str("overall_level")),
        notes = str("notes") ?: ""
    )

    // ------------------------------------------------------------- findings

    fun insertFindings(list: List<Finding>) {
        if (list.isEmpty()) return
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (f in list) db.insert("findings", null, findingValues(f))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    private fun findingValues(f: Finding) = ContentValues().apply {
        put("scan_id", f.scanId)
        put("kind", f.kind.name)
        put("level", f.level.name)
        put("title", f.title)
        put("name", f.name)
        put("location", f.location)
        put("uri", f.uri)
        put("storage_kind", f.storageKind)
        put("parent_uri", f.parentUri)
        put("size", f.size)
        put("created_at", f.createdAt)
        put("modified_at", f.modifiedAt)
        put("sha256", f.sha256)
        put("real_type", f.realType)
        put("package_name", f.packageName)
        put("reasons", f.reasons.joinToString("\n"))
        put("is_hidden", if (f.isHidden) 1 else 0)
        put("is_directory", if (f.isDirectory) 1 else 0)
        put("status", f.status.name)
    }

    /**
     * @param minLevel nivel mínimo a devolver (SAFE devuelve todo).
     * @param kind filtra por tipo de hallazgo si no es null.
     * @param hiddenOnly sólo elementos ocultos.
     */
    fun getFindings(
        scanId: Long,
        minLevel: RiskLevel = RiskLevel.SAFE,
        kind: FindingKind? = null,
        hiddenOnly: Boolean = false
    ): List<Finding> {
        val where = StringBuilder("scan_id=?")
        val args = mutableListOf(scanId.toString())
        if (kind != null) { where.append(" AND kind=?"); args.add(kind.name) }
        if (hiddenOnly) where.append(" AND is_hidden=1")
        val levels = RiskLevel.entries.filter { it.weight >= minLevel.weight }
        where.append(" AND level IN (").append(levels.joinToString(",") { "?" }).append(")")
        levels.forEach { args.add(it.name) }
        return readableDatabase.query("findings", null, where.toString(), args.toTypedArray(), null, null, "id ASC")
            .use { c -> buildList { while (c.moveToNext()) add(c.toFinding()) } }
            .sortedWith(compareByDescending<Finding> { it.level.weight }.thenBy { it.name.lowercase() })
    }

    fun getFinding(id: Long): Finding? =
        readableDatabase.query("findings", null, "id=?", arrayOf(id.toString()), null, null, null)
            .use { c -> if (c.moveToFirst()) c.toFinding() else null }

    fun updateFindingStatus(id: Long, status: FindingStatus) {
        writableDatabase.update("findings", ContentValues().apply { put("status", status.name) }, "id=?", arrayOf(id.toString()))
    }

    private fun Cursor.toFinding() = Finding(
        id = long("id"),
        scanId = long("scan_id"),
        kind = FindingKind.valueOf(str("kind") ?: "FILE"),
        level = RiskLevel.fromName(str("level")),
        title = str("title") ?: "",
        name = str("name") ?: "",
        location = str("location") ?: "",
        uri = str("uri"),
        storageKind = str("storage_kind"),
        parentUri = str("parent_uri"),
        size = longOrNull("size"),
        createdAt = longOrNull("created_at"),
        modifiedAt = longOrNull("modified_at"),
        sha256 = str("sha256"),
        realType = str("real_type"),
        packageName = str("package_name"),
        reasons = (str("reasons") ?: "").split("\n").filter { it.isNotBlank() },
        isHidden = int("is_hidden") == 1,
        isDirectory = int("is_directory") == 1,
        status = FindingStatus.fromName(str("status"))
    )

    // ----------------------------------------------------------- signatures

    fun signatureCount(): Long =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM signatures", null).use { c -> if (c.moveToFirst()) c.getLong(0) else 0L }

    fun findSignature(sha256: String): Signature? =
        readableDatabase.query("signatures", null, "sha256=?", arrayOf(sha256.lowercase()), null, null, null)
            .use { c ->
                if (c.moveToFirst()) Signature(c.str("sha256")!!, c.str("name") ?: "", c.str("source") ?: "", c.long("added_at")) else null
            }

    /** Inserta hashes en lote. Devuelve cuántos eran nuevos. */
    fun insertSignatures(hashes: List<Pair<String, String>>, source: String): Int {
        if (hashes.isEmpty()) return 0
        val db = writableDatabase
        var added = 0
        db.beginTransaction()
        try {
            val stmt = db.compileStatement("INSERT OR IGNORE INTO signatures(sha256,name,source,added_at) VALUES(?,?,?,?)")
            val now = System.currentTimeMillis()
            for ((hash, name) in hashes) {
                stmt.clearBindings()
                stmt.bindString(1, hash.lowercase())
                stmt.bindString(2, name)
                stmt.bindString(3, source)
                stmt.bindLong(4, now)
                if (stmt.executeInsert() != -1L) added++
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return added
    }

    fun signatureSources(): List<Pair<String, Long>> =
        readableDatabase.rawQuery("SELECT source, COUNT(*) FROM signatures GROUP BY source ORDER BY source", null)
            .use { c -> buildList { while (c.moveToNext()) add(c.getString(0) to c.getLong(1)) } }

    fun deleteSignatureSource(source: String): Int =
        writableDatabase.delete("signatures", "source=?", arrayOf(source))

    // -------------------------------------------------------------- trusted

    /** Elementos que el usuario marcó como confiables (clave: "app:<paquete>" o "hash:<sha256>"). */
    fun isTrusted(key: String): Boolean =
        readableDatabase.query("trusted", arrayOf("key"), "key=?", arrayOf(key), null, null, null).use { it.moveToFirst() }

    fun setTrusted(key: String, trusted: Boolean) {
        if (trusted) {
            writableDatabase.insertWithOnConflict("trusted", null, ContentValues().apply {
                put("key", key); put("added_at", System.currentTimeMillis())
            }, SQLiteDatabase.CONFLICT_REPLACE)
        } else {
            writableDatabase.delete("trusted", "key=?", arrayOf(key))
        }
    }

    fun trustedKeys(): List<String> =
        readableDatabase.query("trusted", arrayOf("key"), null, null, null, null, "key")
            .use { c -> buildList { while (c.moveToNext()) add(c.getString(0)) } }

    // ----------------------------------------------------------- quarantine

    fun insertQuarantine(q: QuarantineItem): Long = writableDatabase.insert("quarantine", null, ContentValues().apply {
        put("original_name", q.originalName)
        put("original_location", q.originalLocation)
        put("original_uri", q.originalUri)
        put("parent_uri", q.parentUri)
        put("storage_kind", q.storageKind)
        put("mime", q.mime)
        put("sha256", q.sha256)
        put("size", q.size)
        put("quarantined_at", q.quarantinedAt)
        put("stored_file", q.storedFile)
        put("reason", q.reason)
        put("finding_id", q.findingId)
    })

    fun getQuarantine(): List<QuarantineItem> =
        readableDatabase.query("quarantine", null, null, null, null, null, "quarantined_at DESC")
            .use { c -> buildList { while (c.moveToNext()) add(c.toQuarantine()) } }

    fun getQuarantineItem(id: Long): QuarantineItem? =
        readableDatabase.query("quarantine", null, "id=?", arrayOf(id.toString()), null, null, null)
            .use { c -> if (c.moveToFirst()) c.toQuarantine() else null }

    fun deleteQuarantine(id: Long) {
        writableDatabase.delete("quarantine", "id=?", arrayOf(id.toString()))
    }

    private fun Cursor.toQuarantine() = QuarantineItem(
        id = long("id"),
        originalName = str("original_name") ?: "",
        originalLocation = str("original_location") ?: "",
        originalUri = str("original_uri") ?: "",
        parentUri = str("parent_uri") ?: "",
        storageKind = str("storage_kind") ?: "FILE",
        mime = str("mime"),
        sha256 = str("sha256") ?: "",
        size = long("size"),
        quarantinedAt = long("quarantined_at"),
        storedFile = str("stored_file") ?: "",
        reason = str("reason") ?: "",
        findingId = longOrNull("finding_id")
    )

    // ----------------------------------------------------------- action log

    fun log(action: String, detail: String) {
        writableDatabase.insert("action_log", null, ContentValues().apply {
            put("ts", System.currentTimeMillis())
            put("action", action)
            put("detail", detail)
        })
    }

    fun getLog(limit: Int = 500): List<LogEntry> =
        readableDatabase.query("action_log", null, null, null, null, null, "ts DESC, id DESC", limit.toString())
            .use { c -> buildList { while (c.moveToNext()) add(LogEntry(c.long("id"), c.long("ts"), c.str("action") ?: "", c.str("detail") ?: "")) } }

    // -------------------------------------------------------------- helpers

    private fun Cursor.idx(col: String) = getColumnIndexOrThrow(col)
    private fun Cursor.str(col: String): String? = idx(col).let { if (isNull(it)) null else getString(it) }
    private fun Cursor.long(col: String): Long = getLong(idx(col))
    private fun Cursor.int(col: String): Int = getInt(idx(col))
    private fun Cursor.longOrNull(col: String): Long? = idx(col).let { if (isNull(it)) null else getLong(it) }
}
