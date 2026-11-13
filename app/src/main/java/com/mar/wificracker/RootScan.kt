package com.mar.wificracker

import android.util.Base64
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Авто-подхват файлов хешей из chroot (wifite пишет в папку hs/).
 * Работает только при root (su): ищет .cap/.hc22000/.22000/.16800/.pcapng
 * под типовыми путями NetHunter/Kali и читает их через base64.
 */
object RootScan {

    private val ROOTS = listOf(
        "/data/local/nhsystem",                       // NetHunter kali chroot
        "/data/local/kali-arm64", "/data/local/kalifs",
        "/data/data/com.offsec.nethunter/files",
        "/sdcard", "/storage/emulated/0"
    )
    private val EXT = listOf("cap", "pcap", "pcapng", "hc22000", "22000", "16800")

    fun hasRoot(): Boolean = try {
        val p = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        out.contains("uid=0")
    } catch (_: Exception) { false }

    /** Найти файлы хешей (через su find). */
    fun findFiles(): List<String> {
        val nameExpr = EXT.joinToString(" -o ") { "-iname '*.$it'" }
        val roots = ROOTS.joinToString(" ")
        val cmd = "find $roots -maxdepth 7 -type f \\( $nameExpr \\) 2>/dev/null"
        return runSu(cmd).lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
    }

    /** Прочитать файл через su + base64. */
    fun readFile(path: String): ByteArray? = try {
        val q = path.replace("'", "'\\''")
        val b64 = runSu("base64 '$q' 2>/dev/null").filter { !it.isWhitespace() }
        if (b64.isEmpty()) null else Base64.decode(b64, Base64.DEFAULT)
    } catch (_: Exception) { null }

    private fun runSu(cmd: String): String = try {
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(false).start()
        val r = BufferedReader(InputStreamReader(p.inputStream))
        val sb = StringBuilder(); var line: String?
        while (r.readLine().also { line = it } != null) sb.append(line).append('\n')
        p.waitFor()
        sb.toString()
    } catch (_: Exception) { "" }
}
