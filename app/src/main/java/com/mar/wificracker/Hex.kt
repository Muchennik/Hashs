package com.mar.wificracker

object Hex {
    fun decode(s: String): ByteArray {
        val c = s.trim().filter { !it.isWhitespace() && it != ':' && it != '-' }
        require(c.length % 2 == 0) { "нечётная длина hex: ${c.length}" }
        val out = ByteArray(c.length / 2)
        var i = 0
        while (i < c.length) {
            out[i / 2] = ((hv(c[i]) shl 4) or hv(c[i + 1])).toByte()
            i += 2
        }
        return out
    }
    private fun hv(ch: Char): Int = when (ch) {
        in '0'..'9' -> ch - '0'
        in 'a'..'f' -> ch - 'a' + 10
        in 'A'..'F' -> ch - 'A' + 10
        else -> throw IllegalArgumentException("не hex: $ch")
    }
    fun encode(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}
