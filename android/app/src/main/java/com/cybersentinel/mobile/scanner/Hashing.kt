package com.cybersentinel.mobile.scanner

import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.CancellationException

object Hashing {
    fun sha256(input: InputStream, isCancelled: () -> Boolean = { false }): String {
        val md = MessageDigest.getInstance("SHA-256")
        input.use { s ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                if (isCancelled()) throw CancellationException("cancelado")
                val n = s.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().toHex()
    }

    fun ByteArray.toHex(): String {
        val hex = "0123456789abcdef"
        val out = CharArray(size * 2)
        for (i in indices) {
            val v = this[i].toInt() and 0xFF
            out[i * 2] = hex[v ushr 4]
            out[i * 2 + 1] = hex[v and 0x0F]
        }
        return String(out)
    }

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")
    fun isSha256(s: String) = HEX64.matches(s)
}
