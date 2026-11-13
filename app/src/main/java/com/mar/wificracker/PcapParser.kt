package com.mar.wificracker

import java.io.InputStream

/**
 * Разбор .cap/.pcap (классический) и .pcapng: достаёт из 802.11
 * beacon'ы (SSID по BSSID) и EAPOL-кадры M1/M2 → строит Target'ы
 * (PMKID из M1, рукопожатие из M1+M2). Best-effort, на кривых пакетах
 * просто пропускает. Нужен хотя бы один beacon с SSID для цели.
 */
object PcapParser {

    private class Hs {
        var aNonce: ByteArray? = null
        var sNonce: ByteArray? = null
        var mic: ByteArray? = null
        var eapolZeroed: ByteArray? = null
        var keyver: Int = 2
        var pmkid: ByteArray? = null
        var ap: ByteArray? = null
        var sta: ByteArray? = null
    }

    fun parse(bytes: ByteArray): List<Target> {
        val ssidByBssid = HashMap<String, Pair<String, ByteArray>>()
        val hsByKey = HashMap<String, Hs>()   // ключ = ap|sta

        val frames = when {
            bytes.size >= 4 && le32(bytes, 0) == 0x0A0D0D0AL -> pcapngFrames(bytes)
            else -> pcapFrames(bytes)
        }
        for ((linktype, pkt) in frames) {
            try { handle80211(dot11(linktype, pkt), ssidByBssid, hsByKey) } catch (_: Exception) {}
        }

        val out = ArrayList<Target>()
        for ((_, hs) in hsByKey) {
            val ap = hs.ap ?: continue
            val sta = hs.sta ?: continue
            val sb = ssidByBssid[Target.macStr(ap)] ?: continue
            val (es, esB) = sb
            hs.pmkid?.let {
                out.add(Target(CrackType.PMKID, es, esB, ap, sta, pmkid = it, source = "cap"))
            }
            if (hs.aNonce != null && hs.sNonce != null && hs.mic != null && hs.eapolZeroed != null) {
                out.add(Target(CrackType.HANDSHAKE, es, esB, ap, sta,
                    aNonce = hs.aNonce, sNonce = hs.sNonce, mic = hs.mic,
                    eapolZeroedMic = hs.eapolZeroed, keyver = hs.keyver, source = "cap"))
            }
        }
        return out
    }

    // --- контейнеры ---
    private fun pcapFrames(b: ByteArray): List<Pair<Int, ByteArray>> {
        val res = ArrayList<Pair<Int, ByteArray>>()
        val magic = u32(b, 0)
        val le = magic == 0xA1B2C3D4L || magic == 0xA1B23C4DL
        val linktype = (if (le) le32(b, 20) else be32(b, 20)).toInt()
        var off = 24
        while (off + 16 <= b.size) {
            val inclLen = (if (le) le32(b, off + 8) else be32(b, off + 8)).toInt()
            off += 16
            if (inclLen < 0 || off + inclLen > b.size) break
            res.add(linktype to b.copyOfRange(off, off + inclLen))
            off += inclLen
        }
        return res
    }

    private fun pcapngFrames(b: ByteArray): List<Pair<Int, ByteArray>> {
        val res = ArrayList<Pair<Int, ByteArray>>()
        var off = 0; var linktype = 127
        while (off + 12 <= b.size) {
            val btype = le32(b, off).toInt()
            val blen = le32(b, off + 4).toInt()
            if (blen < 12 || off + blen > b.size) break
            when (btype) {
                0x00000001 -> linktype = (le32(b, off + 8).toInt() and 0xffff) // IDB
                0x00000006 -> { // EPB
                    val capLen = le32(b, off + 20).toInt()
                    val start = off + 28
                    if (start + capLen <= b.size) res.add(linktype to b.copyOfRange(start, start + capLen))
                }
                0x00000003 -> { // simple packet
                    val start = off + 12
                    val capLen = blen - 16
                    if (capLen in 1..(b.size - start)) res.add(linktype to b.copyOfRange(start, start + capLen))
                }
            }
            off += blen
        }
        return res
    }

    /** снять radiotap/prism и вернуть 802.11-кадр. */
    private fun dot11(linktype: Int, pkt: ByteArray): ByteArray = when (linktype) {
        127 -> { val itlen = (pkt[2].toInt() and 0xff) or ((pkt[3].toInt() and 0xff) shl 8); pkt.copyOfRange(itlen, pkt.size) }
        163 -> { val itlen = le32(pkt, 4).toInt(); pkt.copyOfRange(itlen, pkt.size) } // AVS/PPI-ish
        105 -> pkt
        else -> pkt
    }

    private fun handle80211(f: ByteArray, ssids: HashMap<String, Pair<String, ByteArray>>, hs: HashMap<String, Hs>) {
        if (f.size < 24) return
        val fc0 = f[0].toInt() and 0xff
        val fc1 = f[1].toInt() and 0xff
        val type = (fc0 shr 2) and 0x3
        val subtype = (fc0 shr 4) and 0xf
        val toDS = fc1 and 0x1; val fromDS = (fc1 shr 1) and 0x1

        if (type == 0 && (subtype == 8 || subtype == 5)) { // beacon / probe resp
            val bssid = f.copyOfRange(16, 22)
            var p = 24 + 12 // fixed params (timestamp8 + interval2 + caps2)
            while (p + 2 <= f.size) {
                val tag = f[p].toInt() and 0xff; val len = f[p + 1].toInt() and 0xff
                if (p + 2 + len > f.size) break
                if (tag == 0 && len > 0) {
                    val ssidB = f.copyOfRange(p + 2, p + 2 + len)
                    ssids[Target.macStr(bssid)] = String(ssidB, Charsets.UTF_8) to ssidB
                }
                p += 2 + len
            }
            return
        }
        if (type != 2) return // только data
        var hdr = 24
        if (toDS == 1 && fromDS == 1) hdr += 6 // addr4
        if ((subtype and 0x8) != 0) hdr += 2   // QoS
        // LLC/SNAP: AA AA 03 00 00 00 88 8E
        if (hdr + 8 > f.size) return
        if ((f[hdr].toInt() and 0xff) != 0xAA || (f[hdr + 6].toInt() and 0xff) != 0x88 || (f[hdr + 7].toInt() and 0xff) != 0x8E) return
        val eapol = f.copyOfRange(hdr + 8, f.size)
        // определить AP/STA по DS
        val addr1 = f.copyOfRange(4, 10); val addr2 = f.copyOfRange(10, 16)
        val ap: ByteArray; val sta: ByteArray
        if (fromDS == 1) { ap = addr2; sta = addr1 } else { ap = addr1; sta = addr2 }
        parseEapol(eapol, ap, sta, hs)
    }

    private fun parseEapol(e: ByteArray, ap: ByteArray, sta: ByteArray, map: HashMap<String, Hs>) {
        if (e.size < 95 || (e[1].toInt() and 0xff) != 3) return // 802.1X type 3 (EAPOL-Key)
        val bodyLen = ((e[2].toInt() and 0xff) shl 8) or (e[3].toInt() and 0xff)
        val total = 4 + bodyLen
        if (total > e.size) return
        val keyInfo = ((e[5].toInt() and 0xff) shl 8) or (e[6].toInt() and 0xff)
        val keyver = keyInfo and 0x07
        val mic = (keyInfo and 0x100) != 0
        val ack = (keyInfo and 0x080) != 0
        val nonce = e.copyOfRange(17, 49)
        val key = Target.macStr(ap) + "|" + Target.macStr(sta)
        val hs = map.getOrPut(key) { Hs().also { it.ap = ap; it.sta = sta } }

        if (ack && !mic) {
            // M1 (от AP): ANonce + возможный PMKID в key data
            hs.aNonce = nonce
            // key_data_length по смещению 95..96, key_data с 97
            if (e.size >= 97) {
                val kdl = ((e[95].toInt() and 0xff) shl 8) or (e[96].toInt() and 0xff)
                if (97 + kdl <= e.size) hs.pmkid = findPmkid(e.copyOfRange(97, 97 + kdl))
            }
        } else if (mic) {
            // M2 (от STA): SNonce + MIC + EAPOL(обнулить MIC)
            hs.sNonce = nonce
            hs.mic = e.copyOfRange(81, 97)
            hs.keyver = keyver
            val z = e.copyOfRange(0, total)
            for (i in 81 until 81 + 16) if (i < z.size) z[i] = 0
            hs.eapolZeroed = z
        }
    }

    /** PMKID KDE: dd <len> 00 0F AC 04 <16 байт>. */
    private fun findPmkid(kd: ByteArray): ByteArray? {
        var i = 0
        while (i + 2 <= kd.size) {
            val id = kd[i].toInt() and 0xff; val len = kd[i + 1].toInt() and 0xff
            if (id == 0xdd && len >= 20 && i + 2 + len <= kd.size) {
                if ((kd[i + 2].toInt() and 0xff) == 0x00 && (kd[i + 3].toInt() and 0xff) == 0x0F &&
                    (kd[i + 4].toInt() and 0xff) == 0xAC && (kd[i + 5].toInt() and 0xff) == 0x04) {
                    return kd.copyOfRange(i + 6, i + 6 + 16)
                }
            }
            if (len == 0) break
            i += 2 + len
        }
        return null
    }

    private fun u32(b: ByteArray, o: Int) = le32(b, o)
    private fun le32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xff) or ((b[o+1].toLong() and 0xff) shl 8) or
        ((b[o+2].toLong() and 0xff) shl 16) or ((b[o+3].toLong() and 0xff) shl 24)
    private fun be32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xff) shl 24) or ((b[o+1].toLong() and 0xff) shl 16) or
        ((b[o+2].toLong() and 0xff) shl 8) or (b[o+3].toLong() and 0xff)

    fun readAll(ins: InputStream): ByteArray = ins.readBytes()
}
