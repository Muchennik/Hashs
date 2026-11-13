using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WifiCracker;

/// Встроенный CPU-перебор, многопоточный, с чекпоинтами (resume).
public class BuiltinCracker
{
    public Action<long, long, string, long, long, long>? OnProgress; // tried, speed, current, total, elapsedMs, committed
    public Action<Target, string>? OnFound;
    public Action<long, int, long, long, bool>? OnDone;             // tried, found, elapsedMs, committed, exhausted

    volatile bool stop;
    public void RequestStop() => stop = true;
    const int CHUNK = 256;

    public void Run(IList<Target> targets, string wordlistPath, long total, long resumeFrom)
    {
        var groups = targets.GroupBy(t => Hex.Encode(t.SsidBytes)).ToList();
        var solved = new ConcurrentDictionary<string, string>();
        long tried = resumeFrom;
        string current = "";
        var start = DateTime.UtcNow;

        using var reader = new StreamReader(wordlistPath, Encoding.UTF8, true, 1 << 20);
        long dispatched = 0;
        if (resumeFrom > 0) { long sk = 0; while (sk < resumeFrom && reader.ReadLine() != null) sk++; dispatched = sk; tried = sk; }

        var chunkLen = new ConcurrentDictionary<long, int>();
        var doneStarts = new ConcurrentDictionary<long, bool>();
        long committedStart = dispatched;
        long committed = dispatched;
        object readLock = new(); object commitLock = new();

        long lastTried = tried; var lastT = start;
        var progTimer = new Timer(_ =>
        {
            var now = DateTime.UtcNow;
            long t = Interlocked.Read(ref tried);
            double dt = (now - lastT).TotalMilliseconds;
            long sp = dt > 0 ? (long)((t - lastTried) * 1000.0 / dt) : 0;
            lastTried = t; lastT = now;
            OnProgress?.Invoke(t, sp, current, total, (long)(now - start).TotalMilliseconds, Interlocked.Read(ref committed));
        }, null, 400, 400);

        int nthreads = Math.Max(1, Environment.ProcessorCount);
        var tasks = new List<Task>();
        for (int w = 0; w < nthreads; w++)
        {
            tasks.Add(Task.Run(() =>
            {
                while (!stop)
                {
                    long st; var buf = new List<string>(CHUNK);
                    lock (readLock)
                    {
                        st = dispatched;
                        string? l; int n = 0;
                        while (n < CHUNK && (l = reader.ReadLine()) != null) { buf.Add(l); n++; }
                        dispatched += buf.Count;
                    }
                    if (buf.Count == 0) break;
                    chunkLen[st] = buf.Count;
                    foreach (var pwRaw in buf)
                    {
                        if (stop) break;
                        var pw = pwRaw.TrimEnd('\r', '\n');
                        Interlocked.Increment(ref tried);
                        if (pw.Length < 8 || pw.Length > 63) continue;
                        current = pw;
                        foreach (var g in groups)
                        {
                            var unsolved = g.Where(t => !solved.ContainsKey(t.Id)).ToList();
                            if (unsolved.Count == 0) continue;
                            var ssid = Hex.Decode(g.Key);
                            var pmk = Crypto.Pmk(pw, ssid);
                            foreach (var t in unsolved)
                                if (Check(t, pmk)) { solved[t.Id] = pw; OnFound?.Invoke(t, pw); }
                        }
                        if (solved.Count == targets.Count) { stop = true; break; }
                    }
                    if (!stop)
                    {
                        doneStarts[st] = true;
                        lock (commitLock)
                        {
                            while (chunkLen.TryGetValue(committedStart, out var len) && doneStarts.TryRemove(committedStart, out _))
                            { chunkLen.TryRemove(committedStart, out _); committedStart += len; Interlocked.Exchange(ref committed, committedStart); }
                        }
                    }
                }
            }));
        }
        Task.WaitAll(tasks.ToArray());
        progTimer.Dispose();
        bool exhausted = (total > 0 && Interlocked.Read(ref committed) >= total) || solved.Count == targets.Count;
        OnDone?.Invoke(Interlocked.Read(ref tried), solved.Count, (long)(DateTime.UtcNow - start).TotalMilliseconds, Interlocked.Read(ref committed), exhausted);
    }

    static bool Check(Target t, byte[] pmk)
    {
        if (t.Type == CrackType.PMKID) return Crypto.Pmkid(pmk, t.ApMac, t.StaMac).SequenceEqual(t.Pmkid!);
        var kck = Crypto.Kck(pmk, t.ApMac, t.StaMac, t.ANonce!, t.SNonce!);
        return Crypto.Mic(t.Keyver, kck, t.EapolZeroedMic!).Take(16).SequenceEqual(t.Mic!.Take(16));
    }
}
