using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace WifiCracker;

public class MainForm : Form
{
    static readonly Color BG = Color.FromArgb(14, 17, 22);
    static readonly Color SURF = Color.FromArgb(23, 27, 33);
    static readonly Color SURF2 = Color.FromArgb(31, 37, 48);
    static readonly Color ACCENT = Color.FromArgb(255, 138, 43);
    static readonly Color TEXT = Color.FromArgb(230, 237, 243);
    static readonly Color SUB = Color.FromArgb(139, 152, 165);
    static readonly Color OK = Color.FromArgb(63, 185, 80);

    readonly Store store = new();
    TabControl tabs = null!;
    ListView hashList = null!, crackedList = null!;
    Label wordlistLabel = null!, selInfo = null!, posInfo = null!, statusLabel = null!;
    TextBox panel = null!, hashcatPathBox = null!;
    RadioButton rbBuiltin = null!, rbHashcat = null!, rbCpu = null!, rbGpu = null!, rbBoth = null!;
    Button btnStart = null!;
    CheckBox cbRestore = null!;

    string wordlistPath = "";
    BuiltinCracker? builtin;
    HashcatRunner? hashcat;
    volatile bool running;
    readonly Dictionary<string, string> solvedNow = new();

    public MainForm()
    {
        Text = "WifiCracker — только свои сети";
        Size = new Size(860, 620);
        MinimumSize = new Size(720, 520);
        BackColor = BG; ForeColor = TEXT;
        Font = new Font("Segoe UI", 9.5f);
        StartPosition = FormStartPosition.CenterScreen;

        tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildHashesTab());
        tabs.TabPages.Add(BuildCrackTab());
        tabs.TabPages.Add(BuildCrackedTab());
        tabs.TabPages.Add(BuildSettingsTab());
        Controls.Add(tabs);

        RefreshHashes(); RefreshCracked();
    }

    // ---------- стиль ----------
    Button Btn(string t, Color back, Color fore)
    {
        var b = new Button { Text = t, BackColor = back, ForeColor = fore, FlatStyle = FlatStyle.Flat, AutoSize = true, Padding = new Padding(10, 6, 10, 6) };
        b.FlatAppearance.BorderSize = 0; return b;
    }
    TabPage Page(string name) => new TabPage(name) { BackColor = BG, ForeColor = TEXT, Padding = new Padding(10) };

    // ---------- вкладка ХЕШИ ----------
    TabPage BuildHashesTab()
    {
        var p = Page("Хеши");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44, AutoSize = false, BackColor = BG };
        var bImp = Btn("Импорт файла", ACCENT, Color.FromArgb(36, 18, 0));
        var bScan = Btn("Скан папки (hs/)", SURF2, TEXT);
        var bExp = Btn("Экспорт .hc22000", SURF2, TEXT);
        var bClr = Btn("Очистить", SURF2, Color.FromArgb(248, 81, 73));
        bImp.Click += (_, _) => ImportFile();
        bScan.Click += (_, _) => ScanFolder();
        bExp.Click += (_, _) => ExportHashes();
        bClr.Click += (_, _) => { store.ClearHashes(); RefreshHashes(); };
        bar.Controls.AddRange(new Control[] { bImp, bScan, bExp, bClr });

        hashList = new ListView { Dock = DockStyle.Fill, View = View.Details, CheckBoxes = true, FullRowSelect = true, BackColor = SURF, ForeColor = TEXT, BorderStyle = BorderStyle.None, GridLines = false };
        hashList.Columns.Add("SSID", 180);
        hashList.Columns.Add("MAC (BSSID)", 150);
        hashList.Columns.Add("Тип", 100);
        hashList.Columns.Add("Добавлен", 130);
        hashList.Columns.Add("Источник", 120);
        var hint = new Label { Dock = DockStyle.Bottom, Height = 22, ForeColor = SUB, Text = "Отметь галочками хеши для перебора. Delete — удалить выбранные." };
        hashList.KeyDown += (_, e) => { if (e.KeyCode == Keys.Delete) DeleteSelected(); };

        p.Controls.Add(hashList); p.Controls.Add(hint); p.Controls.Add(bar);
        return p;
    }

    void RefreshHashes()
    {
        if (hashList.InvokeRequired) { hashList.BeginInvoke((Action)RefreshHashes); return; }
        hashList.Items.Clear();
        foreach (var t in store.Hashes.Values)
        {
            var it = new ListViewItem(string.IsNullOrEmpty(t.Essid) ? "<скрытый>" : t.Essid) { Tag = t.Id };
            it.SubItems.Add(t.ApMacStr);
            it.SubItems.Add(t.TypeStr);
            it.SubItems.Add(DateTimeOffset.FromUnixTimeMilliseconds(t.AddedAt).LocalDateTime.ToString("dd.MM.yy HH:mm"));
            it.SubItems.Add(t.Source);
            hashList.Items.Add(it);
        }
        UpdateSelInfo();
    }
    void UpdateSelInfo() { if (selInfo != null) selInfo.Text = "Выбрано хешей: " + SelectedTargets().Count; }

    List<Target> SelectedTargets()
    {
        var ids = hashList.CheckedItems.Cast<ListViewItem>().Select(i => (string)i.Tag!).ToHashSet();
        return store.Hashes.Values.Where(t => ids.Contains(t.Id)).ToList();
    }
    void DeleteSelected()
    {
        foreach (ListViewItem i in hashList.SelectedItems) store.RemoveHash((string)i.Tag!);
        RefreshHashes();
    }

    void ImportFile()
    {
        using var d = new OpenFileDialog { Filter = "Capture/hashes|*.cap;*.pcap;*.pcapng;*.hc22000;*.22000;*.16800|Все файлы|*.*", Multiselect = true };
        if (d.ShowDialog() != DialogResult.OK) return;
        int added = 0, total = 0;
        foreach (var path in d.FileNames)
        {
            try
            {
                var bytes = File.ReadAllBytes(path);
                var list = ParseAny(bytes, path);
                total += list.Count;
                added += store.AddTargets(list.Select(t => { t.Source = "file:" + Path.GetFileName(path); return t; }));
            }
            catch { }
        }
        RefreshHashes();
        MessageBox.Show($"Найдено {total}, добавлено новых {added}", "Импорт");
    }

    void ScanFolder()
    {
        using var d = new FolderBrowserDialog { Description = "Папка с файлами wifite (hs/)" };
        if (d.ShowDialog() != DialogResult.OK) return;
        int added = 0, total = 0, files = 0;
        var exts = new[] { ".cap", ".pcap", ".pcapng", ".hc22000", ".22000", ".16800" };
        foreach (var path in Directory.EnumerateFiles(d.SelectedPath, "*.*", SearchOption.AllDirectories)
                     .Where(f => exts.Contains(Path.GetExtension(f).ToLowerInvariant())))
        {
            try { var bytes = File.ReadAllBytes(path); var list = ParseAny(bytes, path); files++; total += list.Count;
                  added += store.AddTargets(list.Select(t => { t.Source = "scan:" + Path.GetFileName(path); return t; })); }
            catch { }
        }
        RefreshHashes();
        MessageBox.Show($"Файлов {files}, найдено {total}, добавлено {added}", "Скан папки");
    }

    static List<Target> ParseAny(byte[] bytes, string path)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        var head = System.Text.Encoding.Latin1.GetString(bytes, 0, Math.Min(bytes.Length, 16));
        List<Target> list;
        if (head.StartsWith("WPA*") || name.EndsWith(".hc22000") || name.EndsWith(".22000") || name.EndsWith(".16800"))
            list = Hc22000Parser.Parse(System.Text.Encoding.UTF8.GetString(bytes));
        else list = PcapParser.Parse(bytes);
        if (list.Count == 0) { try { list = PcapParser.Parse(bytes); } catch { } }
        if (list.Count == 0) { try { list = Hc22000Parser.Parse(System.Text.Encoding.UTF8.GetString(bytes)); } catch { } }
        return list;
    }

    void ExportHashes()
    {
        if (store.Hashes.Count == 0) { MessageBox.Show("Нет хешей"); return; }
        using var d = new SaveFileDialog { Filter = "hashcat 22000|*.hc22000", FileName = "wifi_hashes.hc22000" };
        if (d.ShowDialog() != DialogResult.OK) return;
        var sel = SelectedTargets();
        var ids = sel.Count > 0 ? sel.Select(t => t.Id) : null;
        File.WriteAllText(d.FileName, store.ExportHc22000(ids));
        MessageBox.Show("Экспортировано: " + d.FileName, "Экспорт");
    }

    // ---------- вкладка ПЕРЕБОР ----------
    TabPage BuildCrackTab()
    {
        var p = Page("Перебор");
        var top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 160, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = BG };

        wordlistLabel = new Label { Text = "Словарь: не выбран", ForeColor = TEXT, AutoSize = true };
        var bWl = Btn("Выбрать словарь (.txt)", ACCENT, Color.FromArgb(36, 18, 0));
        bWl.Click += (_, _) => { using var d = new OpenFileDialog { Filter = "Словарь|*.txt;*.lst;*.dic|Все|*.*" }; if (d.ShowDialog() == DialogResult.OK) { wordlistPath = d.FileName; wordlistLabel.Text = "Словарь: " + Path.GetFileName(wordlistPath); UpdatePosInfo(); } };

        var engRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        rbBuiltin = new RadioButton { Text = "Встроенный CPU", Checked = store.Settings.Engine != "hashcat", ForeColor = TEXT, AutoSize = true };
        rbHashcat = new RadioButton { Text = "hashcat", Checked = store.Settings.Engine == "hashcat", ForeColor = TEXT, AutoSize = true };
        engRow.Controls.AddRange(new Control[] { new Label { Text = "Движок:", ForeColor = SUB, AutoSize = true, Padding = new Padding(0, 6, 6, 0) }, rbBuiltin, rbHashcat });

        var devRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        rbCpu = new RadioButton { Text = "CPU", ForeColor = TEXT, AutoSize = true, Checked = store.Settings.Device == "cpu" };
        rbGpu = new RadioButton { Text = "GPU", ForeColor = TEXT, AutoSize = true, Checked = store.Settings.Device == "gpu" };
        rbBoth = new RadioButton { Text = "Оба", ForeColor = TEXT, AutoSize = true, Checked = store.Settings.Device == "both" };
        devRow.Controls.AddRange(new Control[] { new Label { Text = "hashcat устройство:", ForeColor = SUB, AutoSize = true, Padding = new Padding(0, 6, 6, 0) }, rbCpu, rbGpu, rbBoth });
        cbRestore = new CheckBox { Text = "продолжить hashcat (--restore)", ForeColor = SUB, AutoSize = true };

        void SyncDev() { bool hc = rbHashcat.Checked; rbCpu.Enabled = rbGpu.Enabled = rbBoth.Enabled = cbRestore.Enabled = hc; }
        rbHashcat.CheckedChanged += (_, _) => SyncDev();
        rbBuiltin.CheckedChanged += (_, _) => SyncDev();

        selInfo = new Label { Text = "Выбрано хешей: 0", ForeColor = SUB, AutoSize = true };
        posInfo = new Label { Text = "", ForeColor = ACCENT, AutoSize = true };

        var btnRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        btnStart = Btn("Старт", ACCENT, Color.FromArgb(36, 18, 0));
        var btnReset = Btn("Сбросить позицию", SURF2, TEXT);
        btnStart.Click += (_, _) => { if (running) StopCrack(); else StartCrack(); };
        btnReset.Click += (_, _) => { if (!string.IsNullOrEmpty(wordlistPath)) { store.ClearPos(CrackKey()); UpdatePosInfo(); MessageBox.Show("Позиция сброшена"); } };
        btnRow.Controls.AddRange(new Control[] { btnStart, btnReset });

        top.Controls.AddRange(new Control[] { bWl, wordlistLabel, engRow, devRow, cbRestore, selInfo, posInfo, btnRow });

        statusLabel = new Label { Dock = DockStyle.Top, Height = 24, ForeColor = ACCENT, Text = "готов", Padding = new Padding(2, 4, 2, 0) };
        panel = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = SURF, ForeColor = TEXT, BorderStyle = BorderStyle.None, Font = new Font("Consolas", 10f) };

        p.Controls.Add(panel); p.Controls.Add(statusLabel); p.Controls.Add(top);
        SyncDev();
        tabs.SelectedIndexChanged += (_, _) => { UpdateSelInfo(); UpdatePosInfo(); };
        return p;
    }

    string CrackKey()
    {
        var ids = SelectedTargets().Select(t => t.Id).OrderBy(x => x);
        return wordlistPath + "|" + string.Join(",", ids);
    }
    void UpdatePosInfo()
    {
        if (posInfo == null) return;
        if (string.IsNullOrEmpty(wordlistPath) || SelectedTargets().Count == 0) { posInfo.Text = ""; return; }
        var pos = store.GetPos(CrackKey());
        posInfo.Text = pos > 0 ? $"Сохранённая позиция: {pos:n0} — продолжит отсюда" : "";
    }

    void StartCrack()
    {
        var tgts = SelectedTargets();
        if (tgts.Count == 0) { MessageBox.Show("Отметь хеши на вкладке «Хеши»"); return; }
        if (string.IsNullOrEmpty(wordlistPath)) { MessageBox.Show("Выбери словарь"); return; }
        solvedNow.Clear();
        store.Settings.Engine = rbHashcat.Checked ? "hashcat" : "builtin";
        store.Settings.Device = rbCpu.Checked ? "cpu" : rbGpu.Checked ? "gpu" : "both";
        store.SaveSettings();
        running = true; btnStart.Text = "Стоп";

        if (rbHashcat.Checked) RunHashcat(tgts);
        else RunBuiltin(tgts);
    }

    void RunBuiltin(List<Target> tgts)
    {
        var key = CrackKey();
        long resume = store.GetPos(key);
        long total = 0;
        var th = new Thread(() =>
        {
            try { using var sr = new StreamReader(wordlistPath); while (sr.ReadLine() != null) total++; } catch { }
            var eng = new BuiltinCracker(); builtin = eng;
            eng.OnProgress = (tried, sp, cur, tot, el, committed) =>
            {
                store.SetPos(key, committed);
                SetPanel(BuildPanelCpu(tgts, tried, sp, cur, tot, el, committed, false));
            };
            eng.OnFound = (t, pw) => { solvedNow[t.Id] = pw; store.AddCracked(new Cracked { Essid = t.Essid, ApMac = t.ApMacStr, Type = t.TypeStr, Password = pw }); BeginInvoke((Action)RefreshCracked); };
            eng.OnDone = (tried, found, el, committed, exhausted) =>
            {
                if (exhausted) store.ClearPos(key); else store.SetPos(key, committed);
                SetPanel(BuildPanelCpu(tgts, tried, 0, "", tried, el, committed, true) + (exhausted ? $"\r\n\r\nГотово. Найдено: {found}" : $"\r\n\r\nОстановлено на {committed:n0}."));
                EndRun();
            };
            eng.Run(tgts, wordlistPath, total, resume);
        }) { IsBackground = true };
        th.Start();
    }

    void RunHashcat(List<Target> tgts)
    {
        var hp = store.Settings.HashcatPath;
        if (string.IsNullOrWhiteSpace(hp) || !File.Exists(hp)) { MessageBox.Show("Укажи путь к hashcat.exe на вкладке «Настройки»"); EndRun(); return; }
        string dev = rbCpu.Checked ? "cpu" : rbGpu.Checked ? "gpu" : "both";
        bool restore = cbRestore.Checked;
        var th = new Thread(() =>
        {
            var hc = new HashcatRunner(); hashcat = hc;
            hc.OnProgress = (speed, cur, tot, rec) => SetPanel(BuildPanelHc(tgts, speed, cur, tot, rec));
            hc.OnFound = (t, pw) => { solvedNow[t.Id] = pw; store.AddCracked(new Cracked { Essid = t.Essid, ApMac = t.ApMacStr, Type = t.TypeStr, Password = pw }); BeginInvoke((Action)RefreshCracked); };
            hc.OnLog = msg => SetStatus(msg);
            hc.OnDone = (code, msg) => { SetPanel(PanelText() + $"\r\n\r\n{msg} (код {code})"); EndRun(); };
            hc.Run(hp, tgts, wordlistPath, dev, restore);
        }) { IsBackground = true };
        th.Start();
    }

    void StopCrack() { builtin?.RequestStop(); hashcat?.RequestStop(); SetStatus("Остановка…"); }
    void EndRun() { if (InvokeRequired) { BeginInvoke((Action)EndRun); return; } running = false; btnStart.Text = "Старт"; UpdatePosInfo(); }

    string BuildPanelCpu(List<Target> tgts, long tried, long speed, string current, long total, long elapsed, long committed, bool done)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine(done ? "[ завершено · встроенный CPU ]" : "[ идёт перебор · встроенный CPU ]");
        sb.AppendLine($"Время:    {FmtTime(elapsed)}");
        sb.Append($"Ключи:    {tried:n0}");
        if (total > 0) sb.Append($" / {total:n0}  ({(tried * 100.0 / total):0.0}%)");
        sb.AppendLine();
        var eta = speed > 0 && total > tried ? FmtTime((total - tried) / speed * 1000) : "—";
        sb.AppendLine($"Скорость: {speed:n0} кл/с     ETA: {eta}");
        sb.AppendLine($"Текущий:  {(current.Length > 32 ? current.Substring(0, 32) : current)}");
        sb.AppendLine($"Чекпоинт: {committed:n0}");
        sb.AppendLine(); sb.AppendLine("Цели:");
        AppendTargets(sb, tgts);
        return sb.ToString();
    }
    string BuildPanelHc(List<Target> tgts, long speed, long cur, long total, long rec)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("[ идёт перебор · hashcat ]");
        sb.Append($"Ключи:    {cur:n0}");
        if (total > 0) sb.Append($" / {total:n0}  ({(cur * 100.0 / Math.Max(total,1)):0.0}%)");
        sb.AppendLine();
        sb.AppendLine($"Скорость: {speed:n0} H/s");
        sb.AppendLine($"Найдено:  {rec}");
        sb.AppendLine(); sb.AppendLine("Цели:");
        AppendTargets(sb, tgts);
        return sb.ToString();
    }
    void AppendTargets(System.Text.StringBuilder sb, List<Target> tgts)
    {
        foreach (var t in tgts)
            sb.AppendLine(solvedNow.TryGetValue(t.Id, out var pw) ? $" [+] {t.Essid}  ->  {pw}" : $" [ ] {t.Essid}  ({t.ApMacStr})");
    }
    static string FmtTime(long ms) { long s = ms / 1000; return $"{s / 3600:00}:{(s % 3600) / 60:00}:{s % 60:00}"; }

    void SetPanel(string s) { if (panel.InvokeRequired) { panel.BeginInvoke((Action)(() => panel.Text = s)); } else panel.Text = s; }
    string PanelText() => panel.Text;
    void SetStatus(string s) { if (statusLabel.InvokeRequired) statusLabel.BeginInvoke((Action)(() => statusLabel.Text = s)); else statusLabel.Text = s; }

    // ---------- вкладка ВЗЛОМАНО ----------
    TabPage BuildCrackedTab()
    {
        var p = Page("Взломано");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44, BackColor = BG };
        var bCopy = Btn("Копировать всё", SURF2, TEXT);
        var bClr = Btn("Очистить", SURF2, Color.FromArgb(248, 81, 73));
        bCopy.Click += (_, _) => { if (store.Cracked.Count == 0) return; Clipboard.SetText(string.Join("\r\n", store.Cracked.Select(c => $"{c.Essid}\t{c.ApMac}\t{c.Password}"))); MessageBox.Show("Скопировано"); };
        bClr.Click += (_, _) => { store.ClearCracked(); RefreshCracked(); };
        bar.Controls.AddRange(new Control[] { bCopy, bClr });

        crackedList = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, BackColor = SURF, ForeColor = TEXT, BorderStyle = BorderStyle.None };
        crackedList.Columns.Add("SSID", 180);
        crackedList.Columns.Add("MAC", 150);
        crackedList.Columns.Add("Тип", 100);
        crackedList.Columns.Add("Пароль", 180);
        crackedList.Columns.Add("Найден", 130);
        p.Controls.Add(crackedList); p.Controls.Add(bar);
        return p;
    }
    void RefreshCracked()
    {
        if (crackedList.InvokeRequired) { crackedList.BeginInvoke((Action)RefreshCracked); return; }
        crackedList.Items.Clear();
        foreach (var c in Enumerable.Reverse(store.Cracked))
        {
            var it = new ListViewItem(string.IsNullOrEmpty(c.Essid) ? "<скрытый>" : c.Essid);
            it.SubItems.Add(c.ApMac); it.SubItems.Add(c.Type);
            var pwItem = it.SubItems.Add(c.Password); pwItem.ForeColor = OK;
            it.SubItems.Add(DateTimeOffset.FromUnixTimeMilliseconds(c.FoundAt).LocalDateTime.ToString("dd.MM.yy HH:mm"));
            crackedList.Items.Add(it);
        }
    }

    // ---------- вкладка НАСТРОЙКИ ----------
    TabPage BuildSettingsTab()
    {
        var p = Page("Настройки");
        var lbl = new Label { Text = "Путь к hashcat.exe (для GPU/CPU через hashcat):", ForeColor = TEXT, AutoSize = true, Location = new Point(12, 16) };
        hashcatPathBox = new TextBox { Text = store.Settings.HashcatPath, BackColor = SURF, ForeColor = TEXT, BorderStyle = BorderStyle.FixedSingle, Width = 560, Location = new Point(12, 42) };
        var bBrowse = Btn("Обзор…", SURF2, TEXT); bBrowse.Location = new Point(580, 40);
        bBrowse.Click += (_, _) => { using var d = new OpenFileDialog { Filter = "hashcat|hashcat.exe|exe|*.exe" }; if (d.ShowDialog() == DialogResult.OK) hashcatPathBox.Text = d.FileName; };
        var bSave = Btn("Сохранить", ACCENT, Color.FromArgb(36, 18, 0)); bSave.Location = new Point(12, 78);
        bSave.Click += (_, _) => { store.Settings.HashcatPath = hashcatPathBox.Text.Trim(); store.SaveSettings(); MessageBox.Show("Сохранено"); };
        var info = new Label { ForeColor = SUB, AutoSize = true, MaximumSize = new Size(760, 0), Location = new Point(12, 120),
            Text = "hashcat — бесплатный, качается с hashcat.net. Для твоей RTX 4050 ставь GPU (или «Оба» вместе с 12450H). Встроенный CPU работает без hashcat, но медленнее.\n\nДанные (хеши, найденные пароли, позиции) хранятся в %APPDATA%\\WifiCracker.\n\nИспользуй только на своих сетях или с письменного разрешения." };
        p.Controls.AddRange(new Control[] { lbl, hashcatPathBox, bBrowse, bSave, info });
        return p;
    }
}
