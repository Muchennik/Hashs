package com.mar.wificracker

import java.io.BufferedReader
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Многопоточный перебор с чекпоинтами. Словарь раздаётся чанками по 256 строк;
 * фиксируется только сплошь пройденный префикс (committed) — поэтому резюм
 * никогда не пропускает строки (в худшем случае перепроверит чанк-другой).
 */
class CrackEngine(
    private val targets: List<Target>,
    private val threads: Int = Runtime.getRuntime().availableProcessors()
) {
    interface Listener {
        fun onProgress(tried: Long, speed: Long, current: String, total: Long, elapsedMs: Long, committed: Long)
        fun onFound(target: Target, password: String)
        fun onDone(tried: Long, foundCount: Int, elapsedMs: Long, committed: Long, exhausted: Boolean)
        fun onLog(msg: String)
    }

    private val stop = AtomicBoolean(false)
    fun requestStop() { stop.set(true) }

    private val CHUNK = 256

    fun run(reader: BufferedReader, total: Long, resumeFrom: Long, listener: Listener) {
        val groups = targets.groupBy { Hex.encode(it.ssidBytes) }
        val groupList = groups.entries.map { Pair(Hex.decode(it.key), it.value) }
        val solved = ConcurrentHashMap<Target, String>()
        val tried = AtomicLong(0)
        val current = AtomicReference("")
        val lock = Object()
        val tStart = System.currentTimeMillis()
        val fastOk = Crypto.fastPathOk()

        // пропустить уже пройденное
        var dispatched = 0L
        if (resumeFrom > 0) {
            var skipped = 0L
            while (skipped < resumeFrom) { if (reader.readLine() == null) break; skipped++ }
            dispatched = skipped; tried.set(skipped)
        }
        // committed-трекер: старт->длина, множество завершённых стартов
        val chunkLen = ConcurrentHashMap<Long, Int>()
        val doneStarts = ConcurrentHashMap.newKeySet<Long>()
        var committedStart = dispatched
        val committed = AtomicLong(dispatched)
        val commitLock = Object()

        val pool = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(threads)

        Thread {
            var last = tried.get(); var lastT = tStart
            while (!stop.get()) {
                try { Thread.sleep(400) } catch (_: Exception) { break }
                val now = System.currentTimeMillis(); val t = tried.get()
                val sp = if (now > lastT) (t - last) * 1000 / (now - lastT) else 0
                listener.onProgress(t, sp, current.get(), total, now - tStart, committed.get())
                last = t; lastT = now
            }
        }.also { it.isDaemon = true; it.start() }

        repeat(threads) {
            pool.execute {
                try {
                    while (!stop.get()) {
                        val start: Long
                        val buf = ArrayList<String>(CHUNK)
                        synchronized(lock) {
                            start = dispatched
                            var n = 0
                            while (n < CHUNK) { val l = reader.readLine() ?: break; buf.add(l); n++ }
                            dispatched += buf.size
                        }
                        if (buf.isEmpty()) break
                        chunkLen[start] = buf.size
                        var lastPw = ""
                        for (pwRaw in buf) {
                            if (stop.get()) break
                            val pw = pwRaw.trimEnd('\r', '\n')
                            tried.incrementAndGet()
                            if (pw.length !in 8..63) continue
                            lastPw = pw
                            for ((ssidB, tlist) in groupList) {
                                var anyUnsolved = false
                                for (t in tlist) if (!solved.containsKey(t)) { anyUnsolved = true; break }
                                if (!anyUnsolved) continue
                                val pmk = if (fastOk && Crypto.isAscii(pw)) Crypto.pmkFast(pw, ssidB) else Crypto.pmk(pw, ssidB)
                                for (t in tlist) if (!solved.containsKey(t) && check(t, pmk)) { solved[t] = pw; listener.onFound(t, pw) }
                            }
                            if (solved.size == targets.size) { stop.set(true); break }
                        }
                        current.set(lastPw)
                        // отметить чанк завершённым и продвинуть committed по сплошному префиксу
                        if (!stop.get()) {
                            doneStarts.add(start)
                            synchronized(commitLock) {
                                while (true) {
                                    val len = chunkLen[committedStart] ?: break
                                    if (!doneStarts.remove(committedStart)) break
                                    chunkLen.remove(committedStart)
                                    committedStart += len
                                    committed.set(committedStart)
                                }
                            }
                        }
                    }
                } catch (e: Exception) { listener.onLog("поток: ${e.message}") }
                finally { latch.countDown() }
            }
        }
        latch.await(); pool.shutdownNow(); stop.set(true)
        val exhausted = total > 0 && committed.get() >= total || solved.size == targets.size
        listener.onDone(tried.get(), solved.size, System.currentTimeMillis() - tStart, committed.get(), exhausted)
    }

    private fun check(t: Target, pmk: ByteArray): Boolean = when (t.type) {
        CrackType.PMKID -> Crypto.pmkid(pmk, t.apMac, t.staMac).contentEquals(t.pmkid)
        CrackType.HANDSHAKE -> {
            val kck = Crypto.kck(pmk, t.apMac, t.staMac, t.aNonce!!, t.sNonce!!)
            Crypto.mic(t.keyver, kck, t.eapolZeroedMic!!).copyOf(16).contentEquals(t.mic!!.copyOf(16))
        }
    }
}
