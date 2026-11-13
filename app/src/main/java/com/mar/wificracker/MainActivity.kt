package com.mar.wificracker

import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.*
import android.widget.*
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.mar.wificracker.Ui.dp
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {

    private lateinit var store: Store
    private val ui = Handler(Looper.getMainLooper())
    private lateinit var content: FrameLayout
    private val df = SimpleDateFormat("dd.MM.yy HH:mm", Locale.US)

    private val selected = HashSet<String>()
    private var wordlistUri: Uri? = null
    private var wordlistName: String = "—"
    private var engine: CrackEngine? = null
    private var running = false
    private var tab = 0

    // aircrack-панель состояние
    private val solvedNow = HashMap<String, String>()
    private var crackLog: TextView? = null

    private val pickCapture = registerForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        u?.let { importCapture(it) }
    }
    private val pickWordlist = registerForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        u?.let { wordlistUri = it; wordlistName = it.lastPathSegment ?: "словарь"; render() }
    }
    private val exportDoc = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { u ->
        u?.let { doExport(it) }
    }

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        store = Store(this)
        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setBackgroundColor(Ui.BG)
        root.fitsSystemWindows = true

        // шапка
        val header = Ui.tv(this, "WifiCracker", 20f, Ui.TEXT, true)
        header.setPadding(dp(16), dp(14), dp(16), dp(2))
        root.addView(header)
        val sub = Ui.tv(this, "WPA/WPA2 перебор по словарю · только свои сети", 12f, Ui.SUB)
        sub.setPadding(dp(16), 0, dp(16), dp(10))
        root.addView(sub)

        // табы
        val tabs = LinearLayout(this); tabs.orientation = LinearLayout.HORIZONTAL
        tabs.setPadding(dp(10), 0, dp(10), dp(8))
        val names = listOf("Хеши", "Перебор", "Взломано")
        val tabBtns = ArrayList<TextView>()
        names.forEachIndexed { i, n ->
            val b = Ui.tv(this, n, 14f, if (i==0) Ui.ACCENT else Ui.SUB, true)
            b.gravity = Gravity.CENTER
            val lp = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f); lp.setMargins(dp(4),0,dp(4),0)
            b.layoutParams = lp; b.setPadding(0, dp(10), 0, dp(10))
            b.setOnClickListener { tab = i; tabBtns.forEachIndexed { j,t -> t.setTextColor(if (j==i) Ui.ACCENT else Ui.SUB) }; render() }
            tabBtns.add(b); tabs.addView(b)
        }
        root.addView(tabs)

        content = FrameLayout(this)
        root.addView(content, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        setContentView(root)
        render()
    }

    private fun render() {
        content.removeAllViews()
        val scroll = ScrollView(content.context); scroll.isFillViewport = true
        val col = LinearLayout(this); col.orientation = LinearLayout.VERTICAL
        col.setPadding(dp(12), dp(4), dp(12), dp(16))
        scroll.addView(col, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        when (tab) {
            0 -> renderHashes(col)
            1 -> renderCrack(col)
            2 -> renderCracked(col)
        }
        content.addView(scroll)
    }

    // ---------- вкладка ХЕШИ ----------
    private fun renderHashes(col: LinearLayout) {
        val bar = LinearLayout(this); bar.orientation = LinearLayout.HORIZONTAL
        val bImp = Ui.button(this, "Импорт"); bImp.setOnClickListener { pickCapture.launch(arrayOf("*/*")) }
        val bExp = Ui.button(this, "Экспорт", Ui.SURFACE2, Ui.TEXT)
        bExp.setOnClickListener {
            if (store.hashes.isEmpty()) { toast("Нет хешей"); return@setOnClickListener }
            exportDoc.launch("wifi_hashes_${System.currentTimeMillis()}.hc22000")
        }
        val bClr = Ui.button(this, "Очистить", Ui.SURFACE2, Ui.DANGER)
        bClr.setOnClickListener { store.clearHashes(); selected.clear(); render() }
        bar.addView(bImp, flex()); bar.addView(space()); bar.addView(bExp, flex()); bar.addView(space()); bar.addView(bClr, flex())
        col.addView(bar); col.addView(gap(10))

        if (store.hashes.isEmpty()) {
            col.addView(Ui.tv(this, "Пусто. Импортируй .cap / .hc22000 / .22000 / .16800 от wifite.", 13f, Ui.SUB))
            return
        }
        col.addView(Ui.tv(this, "Отмеченные пойдут в перебор. Долгий тап — удалить.", 12f, Ui.SUB))
        col.addView(gap(6))
        for (t in store.hashes.values) {
            val c = Ui.card(this)
            val top = LinearLayout(this); top.orientation = LinearLayout.HORIZONTAL; top.gravity = Gravity.CENTER_VERTICAL
            val cb = CheckBox(this); cb.isChecked = selected.contains(t.id)
            cb.setOnCheckedChangeListener { _, b -> if (b) selected.add(t.id) else selected.remove(t.id) }
            top.addView(cb)
            val titleCol = LinearLayout(this); titleCol.orientation = LinearLayout.VERTICAL
            val row1 = LinearLayout(this); row1.orientation = LinearLayout.HORIZONTAL; row1.gravity = Gravity.CENTER_VERTICAL
            row1.addView(Ui.tv(this, t.essid.ifEmpty { "<скрытый SSID>" }, 15f, Ui.TEXT, true))
            row1.addView(spring())
            row1.addView(Ui.badge(this, t.typeStr, if (t.type==CrackType.PMKID) Ui.PMKID else Ui.HS))
            titleCol.addView(row1)
            titleCol.addView(Ui.tv(this, "MAC: ${t.apMacStr}", 12f, Ui.SUB))
            titleCol.addView(Ui.tv(this, "Добавлен: ${df.format(Date(t.addedAt))}   ·   ${t.source}", 11f, Ui.SUB))
            top.addView(titleCol, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            c.addView(top)
            c.setOnLongClickListener { store.removeHash(t.id); selected.remove(t.id); render(); true }
            col.addView(c); col.addView(gap(8))
        }
    }

    private fun importCapture(uri: Uri) {
        thread {
            try {
                val bytes = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                val name = uri.lastPathSegment ?: ""
                val head = String(bytes.copyOf(minOf(bytes.size, 16)), Charsets.ISO_8859_1)
                var list = if (head.startsWith("WPA*") || name.endsWith(".hc22000") || name.endsWith(".22000") || name.endsWith(".16800"))
                    Hc22000Parser.parse(String(bytes, Charsets.UTF_8)) else PcapParser.parse(bytes)
                if (list.isEmpty()) list = try { PcapParser.parse(bytes) } catch (_: Exception) {
                    try { Hc22000Parser.parse(String(bytes, Charsets.UTF_8)) } catch (_: Exception) { emptyList() }
                }
                val added = store.addTargets(list)
                ui.post { toast(if (list.isEmpty()) "Ничего не распознал" else "Добавлено: $added (всего найдено ${list.size})"); render() }
            } catch (e: Exception) { ui.post { toast("Ошибка: ${e.message}") } }
        }
    }

    private fun doExport(uri: Uri) {
        try {
            val ids = if (selected.isEmpty()) null else selected
            val text = store.exportHc22000(ids)
            contentResolver.openOutputStream(uri)!!.use { it.write(text.toByteArray()) }
            toast("Экспортировано в hc22000")
        } catch (e: Exception) { toast("Ошибка экспорта: ${e.message}") }
    }

    // ---------- вкладка ПЕРЕБОР ----------
    private fun renderCrack(col: LinearLayout) {
        val pick = Ui.card(this)
        pick.addView(Ui.tv(this, "Словарь", 13f, Ui.SUB))
        pick.addView(Ui.tv(this, wordlistName, 14f, Ui.TEXT, true))
        val bWl = Ui.button(this, "Выбрать словарь (.txt)"); bWl.setOnClickListener { pickWordlist.launch(arrayOf("*/*")) }
        pick.addView(gap(8)); pick.addView(bWl)
        col.addView(pick); col.addView(gap(10))

        val selCount = selected.size
        val info = Ui.tv(this, "Выбрано хешей: $selCount" + if (selCount==0) " (отметь на вкладке «Хеши»)" else "", 13f, if (selCount==0) Ui.HS else Ui.SUB)
        col.addView(info); col.addView(gap(8))

        val bStart = Ui.button(this, if (running) "Стоп" else "Старт перебор", if (running) Ui.DANGER else Ui.ACCENT, if (running) 0xFF2A0E0C.toInt() else 0xFF08221F.toInt())
        bStart.setOnClickListener { if (running) stopCrack() else startCrack() }
        col.addView(bStart); col.addView(gap(10))

        val panel = Ui.card(this)
        val log = Ui.tv(this, aircrackHeader(), 12f, Ui.TEXT)
        log.typeface = Typeface.MONOSPACE
        crackLog = log
        panel.addView(log)
        col.addView(panel)
    }

    private fun aircrackHeader(): String =
        "ожидание…\n\nвыбери словарь и отмеченные хеши,\nзатем «Старт перебор»."

    private fun startCrack() {
        val wl = wordlistUri ?: run { toast("Выбери словарь"); return }
        val tgts = store.hashes.values.filter { selected.contains(it.id) }
        if (tgts.isEmpty()) { toast("Отметь хеши на вкладке «Хеши»"); return }
        running = true; solvedNow.clear(); render()
        val eng = CrackEngine(tgts); engine = eng
        thread {
            // посчитать строки для %
            var total = 0L
            try { contentResolver.openInputStream(wl)!!.use { ins ->
                val br = BufferedReader(InputStreamReader(ins), 1 shl 20); while (br.readLine()!=null) total++
            } } catch (_: Exception) {}
            try {
                contentResolver.openInputStream(wl)!!.use { ins ->
                    val reader = BufferedReader(InputStreamReader(ins, Charsets.UTF_8), 1 shl 20)
                    eng.run(reader, total, object : CrackEngine.Listener {
                        override fun onProgress(tried: Long, speed: Long, current: String, tot: Long, elapsedMs: Long) {
                            ui.post { crackLog?.text = buildPanel(tgts, tried, speed, current, tot, elapsedMs, false) }
                        }
                        override fun onFound(target: Target, password: String) {
                            solvedNow[target.id] = password
                            store.addCracked(Cracked(target.essid, target.apMacStr, target.typeStr, password))
                            ui.post { toast("НАЙДЕН: ${target.essid} = $password") }
                        }
                        override fun onDone(tried: Long, foundCount: Int, elapsedMs: Long) {
                            ui.post {
                                crackLog?.text = buildPanel(tgts, tried, 0, "", tried, elapsedMs, true) +
                                    "\n\nГотово. Найдено паролей: $foundCount"
                                running = false; render()
                            }
                        }
                        override fun onLog(msg: String) {}
                    })
                }
            } catch (e: Exception) { ui.post { toast("Ошибка: ${e.message}"); running = false; render() } }
        }
    }

    private fun stopCrack() { engine?.requestStop(); toast("Остановка…") }

    private fun buildPanel(tgts: List<Target>, tried: Long, speed: Long, current: String, total: Long, elapsedMs: Long, done: Boolean): String {
        val pct = if (total > 0) (tried * 100.0 / total) else 0.0
        val eta = if (speed > 0 && total > tried) fmtTime(((total - tried) / speed) * 1000) else "—"
        val sb = StringBuilder()
        sb.append(if (done) "[ завершено ]\n" else "[ идёт перебор ]\n")
        sb.append("Время:   ${fmtTime(elapsedMs)}\n")
        sb.append("Ключи:   ${"%,d".format(tried)}")
        if (total > 0) sb.append(" / ${"%,d".format(total)}  (${"%.1f".format(pct)}%)")
        sb.append("\n")
        sb.append("Скорость: ${"%,d".format(speed)} кл/с     ETA: $eta\n")
        sb.append("Текущий: ${current.take(32)}\n\n")
        sb.append("Цели:\n")
        for (t in tgts) {
            val pw = solvedNow[t.id]
            if (pw != null) sb.append(" [+] ${t.essid}  →  $pw\n")
            else sb.append(" [ ] ${t.essid}  (${t.apMacStr})\n")
        }
        return sb.toString()
    }

    private fun fmtTime(ms: Long): String {
        val s = ms / 1000; return "%02d:%02d:%02d".format(s/3600, (s%3600)/60, s%60)
    }

    // ---------- вкладка ВЗЛОМАНО ----------
    private fun renderCracked(col: LinearLayout) {
        val bar = LinearLayout(this); bar.orientation = LinearLayout.HORIZONTAL
        val bCopy = Ui.button(this, "Копировать всё", Ui.SURFACE2, Ui.TEXT)
        bCopy.setOnClickListener {
            if (store.cracked.isEmpty()) { toast("Пусто"); return@setOnClickListener }
            val t = store.cracked.joinToString("\n") { "${it.essid}\t${it.apMac}\t${it.password}" }
            val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
            cm.setPrimaryClip(android.content.ClipData.newPlainText("cracked", t)); toast("Скопировано")
        }
        val bClr = Ui.button(this, "Очистить", Ui.SURFACE2, Ui.DANGER)
        bClr.setOnClickListener { store.clearCracked(); render() }
        bar.addView(bCopy, flex()); bar.addView(space()); bar.addView(bClr, flex())
        col.addView(bar); col.addView(gap(10))

        if (store.cracked.isEmpty()) { col.addView(Ui.tv(this, "Пока ничего не найдено.", 13f, Ui.SUB)); return }
        for (c in store.cracked.reversed()) {
            val card = Ui.card(this)
            val r = LinearLayout(this); r.orientation = LinearLayout.HORIZONTAL; r.gravity = Gravity.CENTER_VERTICAL
            r.addView(Ui.tv(this, c.essid.ifEmpty { "<скрытый>" }, 15f, Ui.TEXT, true))
            r.addView(spring()); r.addView(Ui.badge(this, c.type, if (c.type=="PMKID") Ui.PMKID else Ui.HS))
            card.addView(r)
            card.addView(Ui.tv(this, "MAC: ${c.apMac}", 12f, Ui.SUB))
            val pw = Ui.tv(this, c.password, 16f, Ui.OK, true); pw.typeface = Typeface.MONOSPACE
            pw.setTextIsSelectable(true); card.addView(pw)
            card.addView(Ui.tv(this, df.format(Date(c.foundAt)), 11f, Ui.SUB))
            col.addView(card); col.addView(gap(8))
        }
    }

    // helpers
    private fun flex() = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
    private fun space(): View { val v = View(this); v.layoutParams = LinearLayout.LayoutParams(dp(8), 1); return v }
    private fun spring(): View { val v = View(this); v.layoutParams = LinearLayout.LayoutParams(0, 1, 1f); return v }
    private fun gap(h: Int): View { val v = View(this); v.layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(h)); return v }
    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
