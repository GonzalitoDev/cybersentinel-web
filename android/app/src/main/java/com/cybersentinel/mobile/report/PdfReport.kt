package com.cybersentinel.mobile.report

import android.content.Context
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.os.Build
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.data.Finding
import com.cybersentinel.mobile.data.FindingKind
import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.scanner.StorageAccess
import com.cybersentinel.mobile.util.Format
import java.io.OutputStream

/** Genera el informe PDF con android.graphics.pdf.PdfDocument (sin librerías externas ni conexión). */
class PdfReport(private val context: Context) {

    private val pageW = 595
    private val pageH = 842
    private val margin = 40f

    private val doc = PdfDocument()
    private var page: PdfDocument.Page? = null
    private var y = 0f
    private var pageNumber = 0

    private val title = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 18f; typeface = Typeface.DEFAULT_BOLD; color = Color.rgb(13, 27, 42) }
    private val h2 = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 13f; typeface = Typeface.DEFAULT_BOLD; color = Color.rgb(3, 105, 161) }
    private val body = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 9.5f; color = Color.rgb(30, 30, 30) }
    private val bold = Paint(body).apply { typeface = Typeface.DEFAULT_BOLD }
    private val small = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 8f; color = Color.rgb(90, 90, 90) }
    private val mono = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 7.5f; typeface = Typeface.MONOSPACE; color = Color.rgb(70, 70, 70) }
    private val line = Paint().apply { color = Color.rgb(200, 210, 220); strokeWidth = 0.8f }

    fun write(scanId: Long, out: OutputStream) {
        val db = Database.get(context)
        val scan = db.getScan(scanId) ?: throw IllegalArgumentException("Análisis inexistente")
        val all = db.getFindings(scanId)
        val sigCount = db.signatureCount()
        val hasAccess = StorageAccess.hasAllFilesAccess(context) || StorageAccess.safFolders(context).isNotEmpty()

        newPage()
        text("CyberSentinel Mobile — Informe de seguridad", title, 24f)
        text("Generado: ${Format.dateTime(System.currentTimeMillis())}  ·  Análisis #${scan.id}: ${scan.type.label}", small, 12f)
        text("Dispositivo: ${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · Parche ${Build.VERSION.SECURITY_PATCH}", small, 12f)
        text("Inicio: ${Format.dateTime(scan.startedAt)}  ·  Fin: ${Format.dateTime(scan.finishedAt)}  ·  Estado: ${scan.status.name}", small, 14f)
        rule()

        val current = Recommendations.currentLevel(all)
        section("Resumen")
        kv("Nivel general de seguridad", "${current.label} — ${Recommendations.overallText(current)}")
        kv("Archivos analizados", scan.filesScanned.toString())
        kv("Archivos con SHA-256 calculado", scan.filesHashed.toString())
        kv("Archivos y carpetas ocultos", scan.hiddenCount.toString())
        kv("Amenazas confirmadas (CRÍTICO)", scan.critical.toString())
        kv("Elementos sospechosos", "${scan.high + scan.medium + scan.low} (ALTO ${scan.high} · MEDIO ${scan.medium} · BAJO ${scan.low})")
        kv("Aplicaciones revisadas", scan.appsScanned.toString())
        kv("Elementos no legibles", scan.errors.toString())
        kv("Firmas en la base local", sigCount.toString())
        if (scan.locations.isNotBlank()) kv("Ubicaciones analizadas", scan.locations.replace("\n", "; "))
        if (scan.notes.isNotBlank()) for (n in scan.notes.split("\n")) paragraph("Nota: $n", small)
        space(6f)

        section("Recomendaciones")
        Recommendations.build(scan, all, sigCount, hasAccess).forEachIndexed { i, r -> paragraph("${i + 1}. $r", body) }
        space(6f)

        val confirmed = all.filter { it.level == RiskLevel.CRITICAL }
        section("Amenazas confirmadas (${confirmed.size})")
        if (confirmed.isEmpty()) paragraph("Ninguna. Ningún archivo ni app coincide con firmas de malware de la base local.", body)
        confirmed.forEach { findingBlock(it) }

        val suspicious = all.filter { it.level.weight in 1..3 && it.kind != FindingKind.DEVICE }
        section("Elementos sospechosos (${suspicious.size})")
        if (suspicious.isEmpty()) paragraph("Ninguno.", body)
        suspicious.forEach { findingBlock(it) }

        val hidden = all.filter { it.isHidden }
        section("Archivos y carpetas ocultos (${hidden.size})")
        if (hidden.isEmpty()) paragraph("No se encontraron elementos ocultos en las ubicaciones analizadas.", body)
        hidden.take(300).forEach {
            paragraph("${if (it.isDirectory) "[carpeta]" else "[archivo]"} ${it.location}/${it.name} · ${Format.size(it.size)} · mod. ${Format.dateTime(it.modifiedAt)} · ${it.level.label}", small)
        }
        if (hidden.size > 300) paragraph("… y ${hidden.size - 300} más (ver en la app).", small)

        val deviceChecks = all.filter { it.kind == FindingKind.DEVICE }
        section("Configuración del dispositivo")
        deviceChecks.forEach { paragraph("[${it.level.label}] ${it.title}: ${it.reasons.joinToString(" ")}", body) }

        section("Metodología")
        paragraph(
            "CRÍTICO se asigna sólo cuando el SHA-256 de un archivo o APK coincide exactamente con una firma de la base local. " +
                "ALTO, MEDIO y BAJO surgen de reglas verificables (tipo real por firma de bytes, extensiones engañosas, ubicación, " +
                "permisos y estado de accesibilidad/administración informados por Android). Un nombre extraño por sí solo nunca se " +
                "considera virus. Todo el análisis se hizo en el teléfono, sin conexión: la app no tiene permiso de Internet.", small
        )

        finishPage()
        doc.writeTo(out)
        doc.close()
        db.log("Informe PDF exportado", "Análisis #${scan.id}")
    }

    private fun findingBlock(f: Finding) {
        ensure(40f)
        val kind = when (f.kind) { FindingKind.FILE -> if (f.isDirectory) "Carpeta" else "Archivo"; FindingKind.APP -> "App"; FindingKind.DEVICE -> "Dispositivo" }
        paragraph("[${f.level.label}] $kind: ${f.name} — ${f.title}", bold)
        val meta = buildList {
            if (f.kind == FindingKind.APP) { f.packageName?.let { add("Paquete: $it") }; add("Origen: ${f.location}") }
            else add("Ubicación: ${f.location}")
            f.size?.let { add("Tamaño: ${Format.size(it)}") }
            f.realType?.takeIf { f.kind == FindingKind.FILE }?.let { add("Tipo real: $it") }
            if (f.createdAt != null) add("Creado: ${Format.dateTime(f.createdAt)}")
            if (f.modifiedAt != null) add((if (f.kind == FindingKind.APP) "Actualizada: " else "Modificado: ") + Format.dateTime(f.modifiedAt))
            add("Estado: ${f.status.label}")
        }
        paragraph(meta.joinToString(" · "), small)
        f.sha256?.let { paragraph("SHA-256: $it", mono) }
        f.reasons.filter { it.startsWith("[") }.forEach { paragraph("• $it", small, indent = 10f) }
        space(5f)
    }

    // ------------------------------------------------------------------ layout

    private fun newPage() {
        pageNumber++
        page = doc.startPage(PdfDocument.PageInfo.Builder(pageW, pageH, pageNumber).create())
        y = margin
    }

    private fun finishPage() {
        page?.let {
            it.canvas.drawText("CyberSentinel Mobile · página $pageNumber", margin, pageH - 20f, small)
            doc.finishPage(it)
        }
        page = null
    }

    private fun ensure(h: Float) {
        if (y + h > pageH - 40f) { finishPage(); newPage() }
    }

    private fun space(h: Float) { y += h }

    private fun rule() {
        ensure(8f)
        page!!.canvas.drawLine(margin, y, pageW - margin, y, line)
        y += 10f
    }

    private fun section(name: String) {
        ensure(40f)
        y += 6f
        page!!.canvas.drawText(name, margin, y + h2.textSize, h2)
        y += h2.textSize + 4f
        page!!.canvas.drawLine(margin, y, pageW - margin, y, line)
        y += 8f
    }

    private fun text(s: String, p: Paint, advance: Float) {
        ensure(advance)
        page!!.canvas.drawText(s, margin, y + p.textSize, p)
        y += advance
    }

    private fun kv(k: String, v: String) {
        val keyW = 190f
        val lines = wrap(v, body, pageW - 2 * margin - keyW)
        ensure(lines.size * (body.textSize + 3f))
        page!!.canvas.drawText(k, margin, y + body.textSize, bold)
        for ((i, l) in lines.withIndex()) {
            if (i > 0) ensure(body.textSize + 3f)
            page!!.canvas.drawText(l, margin + keyW, y + body.textSize, body)
            y += body.textSize + 3f
        }
    }

    private fun paragraph(s: String, p: Paint, indent: Float = 0f) {
        for (l in wrap(s, p, pageW - 2 * margin - indent)) {
            ensure(p.textSize + 3f)
            page!!.canvas.drawText(l, margin + indent, y + p.textSize, p)
            y += p.textSize + 3f
        }
    }

    private fun wrap(text: String, p: Paint, width: Float): List<String> {
        val out = mutableListOf<String>()
        for (rawLine in text.split("\n")) {
            var rest = rawLine
            if (rest.isEmpty()) { out += ""; continue }
            while (rest.isNotEmpty()) {
                var n = p.breakText(rest, true, width, null)
                if (n <= 0) n = 1
                if (n < rest.length) {
                    val space = rest.lastIndexOf(' ', n)
                    if (space > 0) n = space
                }
                out += rest.substring(0, n).trimEnd()
                rest = rest.substring(n).trimStart()
            }
        }
        return out
    }
}
