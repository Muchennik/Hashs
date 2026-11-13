package com.mar.wificracker

import java.io.BufferedReader
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Многопоточный перебор. PMK считается раз на (пароль, SSID). */
class CrackEngine(
    private val targets: List<Target>,
    private val threads: Int = Runtime.getRuntime().availableProcessors()
) {
    interface Listener {
        fun onProgress(tried: Long, speed: Long, current: String, total: Long, elapsedMs: Long)
        fun onFound(target: Target, password: String)
        fun onDone(tried: Long, foundCount: Int, elapsedMs: Long)
        fun onLog(msg: String)
    }

    private val stop = AtomicBoolean(false)
    fun requestStop() { stop.set(true) }

    fun run(reader: BufferedReader, total: Long, listener: Listener) {
        val groups = targets.groupBy { Hex.encode(it.ssidBytes) }
        val solved = ConcurrentHashMap<Target, String>()
        val tried = AtomicLong(0)
        val current = AtomicReference("")
        val lock = Object()
        val pool = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(threads)
        val tStart = System.currentTimeMillis()

        Thread {
            var last = 0L; var lastT = tStart
            while (!stop.get()) {
                try { Thread.sleep(400) } catch (_: Exception) { break }
                val now = System.currentTimeMillis(); val t = tried.get()
                val sp = if (now > lastT) (t - last) * 1000 / (now - lastT) else 0
                listener.onProgress(t, sp, current.get(), total, now - tStart)
                last = t; lastT = now
            }
        }.also { it.isDaemon = true; it.start() }

        repeat(threads) {
            pool.execute {
                try {
                    val buf = ArrayList<String>(256)
                    while (!stop.get()) {
                        buf.clear()
                        synchronized(lock) {
                            var n = 0
                            while (n < 256) { val l = reader.readLine() ?: break; buf.add(l); n++ }
                        }
                        if (buf.isEmpty()) break
                        for (pwRaw in buf) {
                            if (stop.get()) break
                            val pw = pwRaw.trimEnd('\r', '\n')
                            tried.incrementAndGet()
                            if (pw.length !in 8..63) continue
                            current.set(pw)
                            for ((ssidHex, tlist) in groups) {
                                val unsolved = tlist.filter { !solved.containsKey(it) }
                                if (unsolved.isEmpty()) continue
                                val pmk = Crypto.pmk(pw, Hex.decode(ssidHex))
                                for (t in unsolved) if (check(t, pmk)) {
                                    solved[t] = pw; listener.onFound(t, pw)
                                }
                            }
                            if (solved.size == targets.size) { stop.set(true); break }
                        }
                    }
                } catch (e: Exception) { listener.onLog("поток: ${e.message}") }
                finally { latch.countDown() }
            }
        }
        latch.await(); pool.shutdownNow(); stop.set(true)
        listener.onDone(tried.get(), solved.size, System.currentTimeMillis() - tStart)
    }

    private fun check(t: Target, pmk: ByteArray): Boolean = when (t.type) {
        CrackType.PMKID -> Crypto.pmkid(pmk, t.apMac, t.staMac).contentEquals(t.pmkid)
        CrackType.HANDSHAKE -> {
            val kck = Crypto.kck(pmk, t.apMac, t.staMac, t.aNonce!!, t.sNonce!!)
            Crypto.mic(t.keyver, kck, t.eapolZeroedMic!!).copyOf(16).contentEquals(t.mic!!.copyOf(16))
        }
    }
}
