package com.mar.wificracker

enum class CrackType { PMKID, HANDSHAKE }

data class Target(
    val type: CrackType,
    val essid: String,
    val ssidBytes: ByteArray,
    val apMac: ByteArray,
    val staMac: ByteArray,
    val pmkid: ByteArray? = null,
    val aNonce: ByteArray? = null,
    val sNonce: ByteArray? = null,
    val mic: ByteArray? = null,
    val eapolZeroedMic: ByteArray? = null,   // EAPOL с обнулённым MIC (как в hc22000)
    val keyver: Int = 2,
    val messagePair: String = "00",
    val addedAt: Long = System.currentTimeMillis(),
    val source: String = ""
) {
    val id: String get() = "${type}_${Hex.encode(apMac)}_${Hex.encode(staMac)}_${Hex.encode(ssidBytes)}"
    val apMacStr: String get() = macStr(apMac)
    val typeStr: String get() = if (type == CrackType.PMKID) "PMKID" else "HANDSHAKE"

    companion object {
        fun macStr(b: ByteArray) = b.joinToString(":") { "%02x".format(it) }
    }
}

data class Cracked(
    val essid: String,
    val apMac: String,
    val type: String,
    val password: String,
    val foundAt: Long = System.currentTimeMillis()
)
