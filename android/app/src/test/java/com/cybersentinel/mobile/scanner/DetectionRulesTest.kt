package com.cybersentinel.mobile.scanner

import com.cybersentinel.mobile.data.RiskLevel
import com.cybersentinel.mobile.data.Signature
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Pruebas de las reglas de detección (se ejecutan en la JVM: ./gradlew test). */
class DetectionRulesTest {

    @get:Rule val tmp = TemporaryFolder()

    private fun verdict(name: String, path: String, file: File, sig: Signature? = null): FileVerdict {
        val content = ContentReader.read({ file.inputStream() }, file.length(), 100L * 1024 * 1024, { false })
        var rt = content.realType
        val zip = if (rt == RealType.ZIP) ZipInspector.inspectFile(file) else null
        zip?.let { rt = it.refinedType }
        return FileRules.evaluate(FileContext(name, path, file.length(), content, rt, zip, null, sig, false, null))
    }

    private fun fakeApk(name: String): File {
        val f = tmp.newFile(name)
        ZipOutputStream(f.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("AndroidManifest.xml")); z.write(ByteArray(8)); z.closeEntry()
            z.putNextEntry(ZipEntry("classes.dex")); z.write("dex\n035".toByteArray()); z.closeEntry()
        }
        return f
    }

    @Test fun eicarIsDetectedAndHashMatches() {
        val f = tmp.newFile("eicar.com")
        f.writeText("X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*")
        val c = ContentReader.read({ f.inputStream() }, f.length(), 1000, { false })
        assertEquals("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", c.sha256)
        assertTrue(c.isEicar)
        assertEquals(RiskLevel.CRITICAL, verdict("eicar.com", "Almacenamiento interno/Download/eicar.com", f).level)
    }

    @Test fun signatureMatchIsCritical() {
        val f = tmp.newFile("a.bin"); f.writeBytes(ByteArray(10))
        val v = verdict("a.bin", "x/a.bin", f, Signature("x", "Prueba", "test", 0))
        assertEquals(RiskLevel.CRITICAL, v.level)
    }

    @Test fun doubleExtensionApkIsHigh() {
        val apk = fakeApk("factura.pdf.apk")
        assertEquals(RiskLevel.HIGH, verdict(apk.name, "Almacenamiento interno/Download/${apk.name}", apk).level)
    }

    @Test fun apkDisguisedAsImageIsHigh() {
        val apk = fakeApk("foto.jpg")
        val v = verdict("foto.jpg", "Almacenamiento interno/DCIM/foto.jpg", apk)
        assertEquals(RiskLevel.HIGH, v.level)
        assertEquals("Extensión engañosa", v.title)
    }

    @Test fun strangeNameAloneIsNeverAboveLow() {
        val png = tmp.newFile("x.png")
        png.writeBytes(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 13, 10, 26, 10) + ByteArray(64))
        val v = verdict("ѕelfie​.png", "Almacenamiento interno/Pictures/x.png", png)
        assertEquals(RiskLevel.LOW, v.level)
    }

    @Test fun normalImageIsSafe() {
        val png = tmp.newFile("ok.png")
        png.writeBytes(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 13, 10, 26, 10) + ByteArray(64))
        assertEquals(RiskLevel.SAFE, verdict("ok.png", "Almacenamiento interno/Pictures/ok.png", png).level)
    }

    @Test fun pdfWithJavascriptIsMedium() {
        val pdf = tmp.newFile("d.pdf")
        pdf.writeText("%PDF-1.4\n" + "x".repeat(200_000) + "/JavaScript")
        assertEquals(RiskLevel.MEDIUM, verdict("d.pdf", "x/d.pdf", pdf).level)
    }

    @Test fun imitationDetection() {
        assertNull(Brands.detectImitation("WhatsApp", "com.whatsapp"))
        assertNotNull(Brands.detectImitation("WhatsApp", "com.fake.wa"))
        assertNotNull(Brands.detectImitation("Chrorne", "com.fake"))
        assertNotNull(Brands.detectImitation("WhatsApp Plus", "com.x"))
        assertNull(Brands.detectImitation("Email", "com.samsung.android.email.provider"))
    }

    @Test fun bankingTrojanPatternIsHigh() {
        val facts = AppFacts(
            "com.evil", "Actualización", "1", Origin.SIDELOADED, "APK manual",
            listOf("android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"),
            setOf("android.permission.READ_SMS"),
            declaresAccessibility = true, accessibilityEnabled = true
        )
        assertEquals(RiskLevel.HIGH, AppRules.evaluate(facts).level)
    }

    @Test fun ordinaryStoreAppIsSafe() {
        val facts = AppFacts("com.spotify.music", "Spotify", "1", Origin.STORE, "Google Play",
            listOf("android.permission.INTERNET"), setOf("android.permission.INTERNET"))
        assertEquals(RiskLevel.SAFE, AppRules.evaluate(facts).level)
    }

    @Test fun trustedNeverHidesConfirmedThreat() {
        val facts = AppFacts("com.m", "M", "1", Origin.SIDELOADED, "x", emptyList(), emptySet(),
            signatureMatch = Signature("aa", "Malware", "test", 0), trusted = true)
        assertEquals(RiskLevel.CRITICAL, AppRules.evaluate(facts).level)
    }
}
