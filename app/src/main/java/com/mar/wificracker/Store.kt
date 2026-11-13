package com.mar.wificracker

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Персистенция в filesDir: hashes.json, cracked.json. */
class Store(ctx: Context) {
    private val hashesFile = File(ctx.filesDir, "hashes.json")
    private val crackedFile = File(ctx.filesDir, "cracked.json")

    val hashes = LinkedHashMap<String, Target>()   // id -> Target
    val cracked = ArrayList<Cracked>()

    init { loadHashes(); loadCracked() }

    fun addTargets(list: List<Target>): Int {
        var added = 0
        for (t in list) if (!hashes.containsKey(t.id)) { hashes[t.id] = t; added++ }
        saveHashes(); return added
    }
    fun removeHash(id: String) { hashes.remove(id); saveHashes() }
    fun clearHashes() { hashes.clear(); saveHashes() }

    fun addCracked(c: Cracked) {
        if (cracked.none { it.apMac == c.apMac && it.essid == c.essid && it.password == c.password }) {
            cracked.add(c); saveCracked()
        }
    }
    fun clearCracked() { cracked.clear(); saveCracked() }

    // --- hc22000 экспорт ---
    fun exportHc22000(ids: Collection<String>? = null): String {
        val sb = StringBuilder()
        val sel = if (ids == null) hashes.values else hashes.values.filter { ids.contains(it.id) }
        for (t in sel) sb.append(toHcLine(t)).append('\n')
        return sb.toString()
    }
    private fun toHcLine(t: Target): String = when (t.type) {
        CrackType.PMKID ->
            "WPA*01*${Hex.encode(t.pmkid!!)}*${Hex.encode(t.apMac)}*${Hex.encode(t.staMac)}*${Hex.encode(t.ssidBytes)}***"
        CrackType.HANDSHAKE ->
            "WPA*02*${Hex.encode(t.mic!!)}*${Hex.encode(t.apMac)}*${Hex.encode(t.staMac)}*" +
            "${Hex.encode(t.ssidBytes)}*${Hex.encode(t.aNonce!!)}*${Hex.encode(t.eapolZeroedMic!!)}*${t.messagePair}"
    }

    // --- persistence ---
    private fun saveHashes() {
        val arr = JSONArray()
        for (t in hashes.values) arr.put(targetToJson(t))
        hashesFile.writeText(arr.toString())
    }
    private fun loadHashes() {
        if (!hashesFile.exists()) return
        try {
            val arr = JSONArray(hashesFile.readText())
            for (i in 0 until arr.length()) { val t = jsonToTarget(arr.getJSONObject(i)); hashes[t.id] = t }
        } catch (_: Exception) {}
    }
    private fun saveCracked() {
        val arr = JSONArray()
        for (c in cracked) arr.put(JSONObject().apply {
            put("essid", c.essid); put("apMac", c.apMac); put("type", c.type)
            put("password", c.password); put("foundAt", c.foundAt)
        })
        crackedFile.writeText(arr.toString())
    }
    private fun loadCracked() {
        if (!crackedFile.exists()) return
        try {
            val arr = JSONArray(crackedFile.readText())
            for (i in 0 until arr.length()) { val o = arr.getJSONObject(i)
                cracked.add(Cracked(o.getString("essid"), o.getString("apMac"),
                    o.optString("type","?"), o.getString("password"), o.optLong("foundAt")))
            }
        } catch (_: Exception) {}
    }

    private fun b(o: JSONObject, k: String): ByteArray? = o.optString(k, "").let { if (it.isEmpty()) null else Hex.decode(it) }
    private fun targetToJson(t: Target) = JSONObject().apply {
        put("type", t.type.name); put("essid", t.essid); put("ssid", Hex.encode(t.ssidBytes))
        put("ap", Hex.encode(t.apMac)); put("sta", Hex.encode(t.staMac))
        t.pmkid?.let { put("pmkid", Hex.encode(it)) }
        t.aNonce?.let { put("anonce", Hex.encode(it)) }
        t.sNonce?.let { put("snonce", Hex.encode(it)) }
        t.mic?.let { put("mic", Hex.encode(it)) }
        t.eapolZeroedMic?.let { put("eapol", Hex.encode(it)) }
        put("keyver", t.keyver); put("mp", t.messagePair)
        put("addedAt", t.addedAt); put("source", t.source)
    }
    private fun jsonToTarget(o: JSONObject) = Target(
        type = CrackType.valueOf(o.getString("type")),
        essid = o.getString("essid"), ssidBytes = Hex.decode(o.getString("ssid")),
        apMac = Hex.decode(o.getString("ap")), staMac = Hex.decode(o.getString("sta")),
        pmkid = b(o,"pmkid"), aNonce = b(o,"anonce"), sNonce = b(o,"snonce"),
        mic = b(o,"mic"), eapolZeroedMic = b(o,"eapol"),
        keyver = o.optInt("keyver",2), messagePair = o.optString("mp","00"),
        addedAt = o.optLong("addedAt", System.currentTimeMillis()), source = o.optString("source","")
    )
}
