using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace WifiCracker;

/// Гоняет hashcat (режим 22000) с выбором устройства CPU/GPU/Both, парсит JSON-статус и найденные пароли.
public class HashcatRunner
{
    public Action<long, long, long, long>? OnProgress;  // speed(H/s), cur, total, recovered
    public Action<Target, string>? OnFound;
    public Action<int, string>? OnDone;                 // exitCode, message
    public Action<string>? OnLog;

    Process? proc;
    volatile bool stop;
    public void RequestStop() { stop = true; try { proc?.Kill(entireProcessTree: true); } catch { } }

    public void Run(string hashcatPath, IList<Target> targets, string wordlistPath, string device, bool restore)
    {
        var tmp = Path.Combine(Path.GetTempPath(), "wificracker");
        Directory.CreateDirectory(tmp);
        var hashFile = Path.Combine(tmp, "targets.hc22000");
        var outFile = Path.Combine(tmp, "cracked.out");
        var potFile = Path.Combine(tmp, "wc.potfile");
        File.WriteAllText(hashFile, string.Join("\n", targets.Select(ToHcLine)) + "\n");
        try { if (File.Exists(outFile)) File.Delete(outFile); } catch { }

        string dflag = device switch { "cpu" => "1", "gpu" => "2", _ => "1,2" };
        var args = new List<string> {
            "-m", "22000", "-a", "0", "-D", dflag, "-w", "3",
            "--status", "--status-json", "--status-timer", "2",
            "--potfile-path", potFile, "--outfile", outFile, "--outfile-format", "3",
            "--quiet"
        };
        if (restore) { args.Add("--session"); args.Add("wc"); args.Add("--restore"); }
        else { args.Add("--session"); args.Add("wc"); }
        args.Add(hashFile); args.Add(wordlistPath);

        var psi = new ProcessStartInfo
        {
            FileName = hashcatPath,
            WorkingDirectory = Path.GetDirectoryName(hashcatPath) ?? tmp,
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var seenCracked = new HashSet<string>();

        proc.OutputDataReceived += (_, e) => { if (e.Data != null) ParseStatus(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) OnLog?.Invoke(e.Data); };

        // следим за outfile на предмет новых паролей
        var watcher = new Timer(_ => ReadCracked(outFile, targets, seenCracked), null, 500, 1000);

        try
        {
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            proc.WaitForExit();
            Thread.Sleep(300);
            ReadCracked(outFile, targets, seenCracked);
            CollectShow(hashcatPath, hashFile, potFile, targets, seenCracked);
            OnDone?.Invoke(proc.ExitCode, stop ? "остановлено" : "hashcat завершил");
        }
        catch (Exception ex) { OnDone?.Invoke(-1, "не удалось запустить hashcat: " + ex.Message); }
        finally { watcher.Dispose(); }
    }

    // Достаёт ВСЕ взломанные пары из potfile через `hashcat --show` (включая найденные ранее).
    void CollectShow(string hashcatPath, string hashFile, string potFile, IList<Target> targets, HashSet<string> seen)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = hashcatPath,
                WorkingDirectory = Path.GetDirectoryName(hashcatPath) ?? Path.GetTempPath(),
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            };
            foreach (var a in new[] { "-m", "22000", "-a", "0", "--show", "--potfile-path", potFile, "--outfile-format", "3", "--quiet", hashFile })
                psi.ArgumentList.Add(a);
            using var pr = Process.Start(psi)!;
            string outp = pr.StandardOutput.ReadToEnd();
            pr.WaitForExit();
            foreach (var raw in outp.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || seen.Contains(line)) continue;
                seen.Add(line);
                int i = line.LastIndexOf(':');
                if (i <= 0) continue;
                var hashPart = line.Substring(0, i); var pw = line.Substring(i + 1);
                var parsed = Hc22000Parser.Parse(hashPart);
                if (parsed.Count == 0) continue;
                var pt = parsed[0];
                var match = targets.FirstOrDefault(t => t.ApMacStr == pt.ApMacStr) ?? pt;
                OnFound?.Invoke(match, pw);
            }
        }
        catch { }
    }

    void ParseStatus(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("{") || !line.Contains("progress")) return;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            long cur = 0, total = 0, rec = 0, speed = 0;
            if (r.TryGetProperty("progress", out var pr) && pr.GetArrayLength() >= 2)
            { cur = pr[0].GetInt64(); total = pr[1].GetInt64(); }
            if (r.TryGetProperty("recovered_hashes", out var rh) && rh.GetArrayLength() >= 1)
                rec = rh[0].GetInt64();
            if (r.TryGetProperty("devices", out var devs))
                foreach (var d in devs.EnumerateArray())
                    if (d.TryGetProperty("speed", out var sp)) speed += sp.GetInt64();
            OnProgress?.Invoke(speed, cur, total, rec);
        }
        catch { }
    }

    void ReadCracked(string outFile, IList<Target> targets, HashSet<string> seen)
    {
        try
        {
            if (!File.Exists(outFile)) return;
            foreach (var raw in File.ReadAllLines(outFile))
            {
                var line = raw.Trim();
                if (line.Length == 0 || seen.Contains(line)) continue;
                seen.Add(line);
                int i = line.LastIndexOf(':');
                if (i <= 0) continue;
                var hashPart = line.Substring(0, i);
                var pw = line.Substring(i + 1);
                var parsed = Hc22000Parser.Parse(hashPart);
                if (parsed.Count == 0) continue;
                var pt = parsed[0];
                var match = targets.FirstOrDefault(t => t.ApMacStr == pt.ApMacStr) ?? pt;
                OnFound?.Invoke(match, pw);
            }
        }
        catch { }
    }

    static string ToHcLine(Target t) => t.Type == CrackType.PMKID
        ? $"WPA*01*{Hex.Encode(t.Pmkid!)}*{Hex.Encode(t.ApMac)}*{Hex.Encode(t.StaMac)}*{Hex.Encode(t.SsidBytes)}***"
        : $"WPA*02*{Hex.Encode(t.Mic!)}*{Hex.Encode(t.ApMac)}*{Hex.Encode(t.StaMac)}*{Hex.Encode(t.SsidBytes)}*{Hex.Encode(t.ANonce!)}*{Hex.Encode(t.EapolZeroedMic!)}*{t.MessagePair}";
}
