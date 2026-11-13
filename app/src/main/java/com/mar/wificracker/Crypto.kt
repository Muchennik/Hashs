package com.mar.wificracker

import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Весь WPA/WPA2-PSK crypto: PBKDF2, PMK, PMKID, PTK(KCK), MIC.
 * PBKDF2 реализован вручную поверх UTF-8 байт пароля — чтобы совпадать
 * со стандартом (SunJCE PBKDF2 режет пароль до 8 бит и ломает не-ASCII).
 */
object Crypto {

    private fun mac(alg: String, key: ByteArray): Mac {
        val m = Mac.getInstance(alg)
        m.init(SecretKeySpec(key, alg))
        return m
    }

    fun hmacSha1(key: ByteArray, msg: ByteArray): ByteArray = mac("HmacSHA1", key).doFinal(msg)
    fun hmacMd5(key: ByteArray, msg: ByteArray): ByteArray = mac("HmacMD5", key).doFinal(msg)

    /** PBKDF2-HMAC-SHA1, стандартный WPA: salt = ssid, iters = 4096, dkLen = 32. */
    fun pbkdf2Sha1(password: ByteArray, salt: ByteArray, iters: Int, dkLen: Int): ByteArray {
        val m = mac("HmacSHA1", password)       // ключ = пароль, переиспользуем
        val hLen = 20
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(blocks * hLen)
        val intbuf = ByteArray(4)
        for (i in 1..blocks) {
            intbuf[0] = (i ushr 24).toByte(); intbuf[1] = (i ushr 16).toByte()
            intbuf[2] = (i ushr 8).toByte();  intbuf[3] = i.toByte()
            m.update(salt); var u = m.doFinal(intbuf)
            val t = u.copyOf()
            for (j in 2..iters) {
                u = m.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            System.arraycopy(t, 0, out, (i - 1) * hLen, hLen)
        }
        return out.copyOf(dkLen)
    }

    /** PMK = PBKDF2(passphrase, ssid, 4096, 32) — точный ручной путь (UTF-8). */
    fun pmk(passphrase: String, ssid: ByteArray): ByteArray =
        pbkdf2Sha1(passphrase.toByteArray(Charsets.UTF_8), ssid, 4096, 32)

    // быстрый путь: весь PBKDF2 одним нативным вызовом Conscrypt (BoringSSL, HW SHA1)
    private val skfTL = ThreadLocal.withInitial { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1") }
    fun pmkFast(passphrase: String, ssid: ByteArray): ByteArray {
        val spec = PBEKeySpec(passphrase.toCharArray(), ssid, 4096, 256)
        return skfTL.get().generateSecret(spec).encoded
    }

    /** true если строка чисто ASCII — тогда быстрый путь совпадает с ручным. */
    fun isAscii(s: String): Boolean { for (c in s) if (c.code > 127) return false; return true }

    /** Самопроверка: быстрый PMK == ручной PMK на ASCII-векторе. */
    fun fastPathOk(): Boolean = try {
        pmkFast("password", "salt1234".toByteArray()).contentEquals(pmk("password", "salt1234".toByteArray()))
    } catch (_: Exception) { false }

    /** PMKID = HMAC-SHA1(PMK, "PMK Name" | AP | STA)[0:16]. */
    fun pmkid(pmk: ByteArray, apMac: ByteArray, staMac: ByteArray): ByteArray {
        val msg = "PMK Name".toByteArray(Charsets.US_ASCII) + apMac + staMac
        return hmacSha1(pmk, msg).copyOf(16)
    }

    /** KCK (первые 16 байт PTK) через PRF-512. */
    fun kck(pmk: ByteArray, apMac: ByteArray, staMac: ByteArray, aNonce: ByteArray, sNonce: ByteArray): ByteArray {
        val a = "Pairwise key expansion".toByteArray(Charsets.US_ASCII)
        val b = minMax(apMac, staMac) + minMax(aNonce, sNonce)
        // PTK = PRF-512: R = HMAC-SHA1(PMK, A | 0x00 | B | i); нам нужны только первые 16 байт (i=0).
        val input = a + byteArrayOf(0) + b + byteArrayOf(0)
        return hmacSha1(pmk, input).copyOf(16)
    }

    /** MIC по keyver: 1=HMAC-MD5, 2=HMAC-SHA1[:16], 3=AES-CMAC[:16]. */
    fun mic(keyver: Int, kck: ByteArray, eapolZeroedMic: ByteArray): ByteArray = when (keyver) {
        1 -> hmacMd5(kck, eapolZeroedMic)
        2 -> hmacSha1(kck, eapolZeroedMic).copyOf(16)
        3 -> aesCmac(kck, eapolZeroedMic).copyOf(16)
        else -> hmacSha1(kck, eapolZeroedMic).copyOf(16)
    }

    private fun minMax(x: ByteArray, y: ByteArray): ByteArray {
        val c = cmp(x, y)
        return if (c <= 0) x + y else y + x
    }
    private fun cmp(x: ByteArray, y: ByteArray): Int {
        for (i in x.indices) {
            val a = x[i].toInt() and 0xff; val b = y[i].toInt() and 0xff
            if (a != b) return a - b
        }
        return 0
    }

    // --- AES-CMAC (RFC 4493) для keyver 3 (WPA2 с AES-128-CMAC) ---
    private fun aesCmac(key: ByteArray, msg: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        fun enc(b: ByteArray) = cipher.doFinal(b)
        val L = enc(ByteArray(16))
        val k1 = dbl(L); val k2 = dbl(k1)
        val n = (msg.size + 15) / 16
        val last: ByteArray
        val complete = msg.isNotEmpty() && msg.size % 16 == 0
        if (complete) {
            last = xor(msg.copyOfRange((n - 1) * 16, n * 16), k1)
        } else {
            val rem = if (n == 0) 0 else msg.size - (n - 1) * 16
            val start = if (n == 0) 0 else (n - 1) * 16
            val padded = ByteArray(16)
            val tail = msg.copyOfRange(start, msg.size)
            System.arraycopy(tail, 0, padded, 0, tail.size)
            padded[tail.size] = 0x80.toByte()
            last = xor(padded, k2)
        }
        var x = ByteArray(16)
        val blocks = if (n == 0) 0 else n - 1
        for (i in 0 until blocks) {
            x = enc(xor(x, msg.copyOfRange(i * 16, i * 16 + 16)))
        }
        return enc(xor(last, x))
    }
    private fun dbl(b: ByteArray): ByteArray {
        val r = ByteArray(16); var carry = 0
        for (i in 15 downTo 0) {
            val v = ((b[i].toInt() and 0xff) shl 1) or carry
            r[i] = v.toByte(); carry = (v ushr 8) and 1
        }
        if ((b[0].toInt() and 0x80) != 0) r[15] = (r[15].toInt() xor 0x87).toByte()
        return r
    }
    private fun xor(a: ByteArray, b: ByteArray): ByteArray {
        val r = ByteArray(a.size); for (i in a.indices) r[i] = (a[i].toInt() xor b[i].toInt()).toByte(); return r
    }
}
