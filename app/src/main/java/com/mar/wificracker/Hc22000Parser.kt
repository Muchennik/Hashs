package com.mar.wificracker

/**
 * Разбор hashcat-форматов, которые отдаёт wifite / hcxpcapngtool:
 *   WPA*01*PMKID*AP*STA*ESSID***            — PMKID (режим 22000, подтип 01)
 *   WPA*02*MIC*AP*STA*ESSID*ANONCE*EAPOL*MP — рукопожатие (подтип 02)
 *   PMKID*AP*STA*ESSID                      — старый формат 16800
 */
object Hc22000Parser {

    fun parse(text: String): List<Target> {
        val out = ArrayList<Target>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            try {
                when {
                    line.startsWith("WPA*01*") -> out.add(parse01(line))
                    line.startsWith("WPA*02*") -> out.add(parse02(line))
                    // 16800: PMKID*AP*STA*ESSID (4 поля, первое 32 hex)
                    line.count { it == '*' } == 3 && line.substringBefore('*').length == 32 ->
                        out.add(parse16800(line))
                }
            } catch (_: Exception) { /* пропускаем битую строку */ }
        }
        return out
    }

    private fun essid(hex: String) = String(Hex.decode(hex), Charsets.UTF_8) to Hex.decode(hex)

    private fun parse01(line: String): Target {
        val p = line.split("*")
        val (es, esB) = essid(p[5])
        return Target(
            type = CrackType.PMKID, essid = es, ssidBytes = esB,
            apMac = Hex.decode(p[3]), staMac = Hex.decode(p[4]),
            pmkid = Hex.decode(p[2]), source = "hc22000"
        )
    }

    private fun parse16800(line: String): Target {
        val p = line.split("*")
        val (es, esB) = essid(p[3])
        return Target(
            type = CrackType.PMKID, essid = es, ssidBytes = esB,
            apMac = Hex.decode(p[1]), staMac = Hex.decode(p[2]),
            pmkid = Hex.decode(p[0]), source = "16800"
        )
    }

    private fun parse02(line: String): Target {
        val p = line.split("*")
        val mic = Hex.decode(p[2])
        val ap = Hex.decode(p[3]); val sta = Hex.decode(p[4])
        val (es, esB) = essid(p[5])
        val aNonce = Hex.decode(p[6])
        val eapol = Hex.decode(p[7])
        // keyver из key_info (big-endian по смещению 5..6 кадра EAPOL)
        val keyInfo = ((eapol[5].toInt() and 0xff) shl 8) or (eapol[6].toInt() and 0xff)
        val keyver = keyInfo and 0x07
        // SNONCE = key_nonce в кадре EAPOL (смещение 17, 32 байта) — он от STA (M2)
        val sNonce = eapol.copyOfRange(17, 17 + 32)
        // обнуляем MIC (смещение 81, 16 байт) для подсчёта
        val z = eapol.copyOf()
        for (i in 81 until 81 + 16) if (i < z.size) z[i] = 0
        val mp = if (p.size > 8) p[8].trim().ifEmpty { "00" } else "00"
        return Target(
            type = CrackType.HANDSHAKE, essid = es, ssidBytes = esB,
            apMac = ap, staMac = sta, aNonce = aNonce, sNonce = sNonce,
            mic = mic, eapolZeroedMic = z, keyver = keyver, messagePair = mp,
            source = "hc22000"
        )
    }
}
