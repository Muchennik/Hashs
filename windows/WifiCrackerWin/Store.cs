using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WifiCracker;

public class Store
{
    readonly string dir;
    readonly string hashesFile, crackedFile, progressFile, settingsFile;
    public Dictionary<string, Target> Hashes = new();
    public List<Cracked> Cracked = new();
    public Dictionary<string, long> Progress = new();
    public Settings Settings = new();

    public Store()
    {
        dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WifiCracker");
        Directory.CreateDirectory(dir);
        hashesFile = Path.Combine(dir, "hashes.json");
        crackedFile = Path.Combine(dir, "cracked.json");
        progressFile = Path.Combine(dir, "progress.json");
        settingsFile = Path.Combine(dir, "settings.json");
        Load();
    }

    public int AddTargets(IEnumerable<Target> list)
    {
        int added = 0;
        foreach (var t in list) if (!Hashes.ContainsKey(t.Id)) { Hashes[t.Id] = t; added++; }
        SaveHashes(); return added;
    }
    public void RemoveHash(string id) { Hashes.Remove(id); SaveHashes(); }
    public void ClearHashes() { Hashes.Clear(); SaveHashes(); }

    public void AddCracked(Cracked c)
    {
        if (!Cracked.Any(x => x.ApMac == c.ApMac && x.Essid == c.Essid && x.Password == c.Password))
        { Cracked.Add(c); SaveCracked(); }
    }
    public void ClearCracked() { Cracked.Clear(); SaveCracked(); }

    public long GetPos(string key) => Progress.TryGetValue(key, out var v) ? v : 0L;
    public void SetPos(string key, long pos) { Progress[key] = pos; SaveProgress(); }
    public void ClearPos(string key) { if (Progress.Remove(key)) SaveProgress(); }

    public string ExportHc22000(IEnumerable<string>? ids = null)
    {
        var sel = ids == null ? Hashes.Values : Hashes.Values.Where(t => ids.Contains(t.Id));
        var lines = sel.Select(ToHcLine);
        return string.Join("\n", lines) + "\n";
    }
    static string ToHcLine(Target t) => t.Type == CrackType.PMKID
        ? $"WPA*01*{Hex.Encode(t.Pmkid!)}*{Hex.Encode(t.ApMac)}*{Hex.Encode(t.StaMac)}*{Hex.Encode(t.SsidBytes)}***"
        : $"WPA*02*{Hex.Encode(t.Mic!)}*{Hex.Encode(t.ApMac)}*{Hex.Encode(t.StaMac)}*{Hex.Encode(t.SsidBytes)}*{Hex.Encode(t.ANonce!)}*{Hex.Encode(t.EapolZeroedMic!)}*{t.MessagePair}";

    // --- persistence ---
    void SaveHashes()
    {
        var arr = new JsonArray();
        foreach (var t in Hashes.Values) arr.Add(TargetToJson(t));
        File.WriteAllText(hashesFile, arr.ToJsonString());
    }
    void SaveCracked()
    {
        var arr = new JsonArray();
        foreach (var c in Cracked) arr.Add(new JsonObject { ["essid"] = c.Essid, ["apMac"] = c.ApMac, ["type"] = c.Type, ["password"] = c.Password, ["foundAt"] = c.FoundAt });
        File.WriteAllText(crackedFile, arr.ToJsonString());
    }
    void SaveProgress()
    {
        var o = new JsonObject();
        foreach (var kv in Progress) o[kv.Key] = kv.Value;
        File.WriteAllText(progressFile, o.ToJsonString());
    }
    public void SaveSettings() => File.WriteAllText(settingsFile, JsonSerializer.Serialize(Settings));

    void Load()
    {
        try { if (File.Exists(hashesFile)) { var arr = JsonNode.Parse(File.ReadAllText(hashesFile))!.AsArray(); foreach (var n in arr) { var t = JsonToTarget(n!.AsObject()); Hashes[t.Id] = t; } } } catch { }
        try { if (File.Exists(crackedFile)) { var arr = JsonNode.Parse(File.ReadAllText(crackedFile))!.AsArray(); foreach (var n in arr) { var o = n!.AsObject(); Cracked.Add(new Cracked { Essid = (string)o["essid"]!, ApMac = (string)o["apMac"]!, Type = (string?)o["type"] ?? "?", Password = (string)o["password"]!, FoundAt = (long?)o["foundAt"] ?? 0 }); } } } catch { }
        try { if (File.Exists(progressFile)) { var o = JsonNode.Parse(File.ReadAllText(progressFile))!.AsObject(); foreach (var kv in o) Progress[kv.Key] = (long)kv.Value!; } } catch { }
        try { if (File.Exists(settingsFile)) Settings = JsonSerializer.Deserialize<Settings>(File.ReadAllText(settingsFile)) ?? new Settings(); } catch { }
    }

    static string? HexOrNull(byte[]? b) => b == null ? null : Hex.Encode(b);
    static byte[]? B(JsonObject o, string k) { var v = (string?)o[k]; return string.IsNullOrEmpty(v) ? null : Hex.Decode(v); }
    static JsonObject TargetToJson(Target t)
    {
        var o = new JsonObject
        {
            ["type"] = t.Type.ToString(), ["essid"] = t.Essid, ["ssid"] = Hex.Encode(t.SsidBytes),
            ["ap"] = Hex.Encode(t.ApMac), ["sta"] = Hex.Encode(t.StaMac),
            ["keyver"] = t.Keyver, ["mp"] = t.MessagePair, ["addedAt"] = t.AddedAt, ["source"] = t.Source
        };
        if (t.Pmkid != null) o["pmkid"] = Hex.Encode(t.Pmkid);
        if (t.ANonce != null) o["anonce"] = Hex.Encode(t.ANonce);
        if (t.SNonce != null) o["snonce"] = Hex.Encode(t.SNonce);
        if (t.Mic != null) o["mic"] = Hex.Encode(t.Mic);
        if (t.EapolZeroedMic != null) o["eapol"] = Hex.Encode(t.EapolZeroedMic);
        return o;
    }
    static Target JsonToTarget(JsonObject o) => new()
    {
        Type = Enum.Parse<CrackType>((string)o["type"]!),
        Essid = (string)o["essid"]!, SsidBytes = Hex.Decode((string)o["ssid"]!),
        ApMac = Hex.Decode((string)o["ap"]!), StaMac = Hex.Decode((string)o["sta"]!),
        Pmkid = B(o, "pmkid"), ANonce = B(o, "anonce"), SNonce = B(o, "snonce"),
        Mic = B(o, "mic"), EapolZeroedMic = B(o, "eapol"),
        Keyver = (int?)o["keyver"] ?? 2, MessagePair = (string?)o["mp"] ?? "00",
        AddedAt = (long?)o["addedAt"] ?? 0, Source = (string?)o["source"] ?? ""
    };
}

public class Settings
{
    public string HashcatPath { get; set; } = "";
    public string Engine { get; set; } = "builtin";   // builtin | hashcat
    public string Device { get; set; } = "gpu";        // cpu | gpu | both
}
