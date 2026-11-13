using System;
using System.Collections.Generic;
using System.Text;

namespace WifiCracker;

public static class Hc22000Parser
{
    public static List<Target> Parse(string text)
    {
        var outp = new List<Target>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            try
            {
                if (line.StartsWith("WPA*01*")) outp.Add(Parse01(line));
                else if (line.StartsWith("WPA*02*")) outp.Add(Parse02(line));
                else if (CountStar(line) == 3 && line.Substring(0, line.IndexOf('*')).Length == 32) outp.Add(Parse16800(line));
            }
            catch { }
        }
        return outp;
    }
    static int CountStar(string s) { int n = 0; foreach (var c in s) if (c == '*') n++; return n; }
    static (string, byte[]) Essid(string hex) { var b = Hex.Decode(hex); return (Encoding.UTF8.GetString(b), b); }

    static Target Parse01(string line)
    {
        var p = line.Split('*');
        var (es, esB) = Essid(p[5]);
        return new Target { Type = CrackType.PMKID, Essid = es, SsidBytes = esB, ApMac = Hex.Decode(p[3]), StaMac = Hex.Decode(p[4]), Pmkid = Hex.Decode(p[2]), Source = "hc22000" };
    }
    static Target Parse16800(string line)
    {
        var p = line.Split('*');
        var (es, esB) = Essid(p[3]);
        return new Target { Type = CrackType.PMKID, Essid = es, SsidBytes = esB, ApMac = Hex.Decode(p[1]), StaMac = Hex.Decode(p[2]), Pmkid = Hex.Decode(p[0]), Source = "16800" };
    }
    static Target Parse02(string line)
    {
        var p = line.Split('*');
        var mic = Hex.Decode(p[2]);
        var ap = Hex.Decode(p[3]); var sta = Hex.Decode(p[4]);
        var (es, esB) = Essid(p[5]);
        var aNonce = Hex.Decode(p[6]);
        var eapol = Hex.Decode(p[7]);
        int keyInfo = ((eapol[5] & 0xff) << 8) | (eapol[6] & 0xff);
        int keyver = keyInfo & 0x07;
        var sNonce = new byte[32]; Array.Copy(eapol, 17, sNonce, 0, 32);
        var z = (byte[])eapol.Clone();
        for (int i = 81; i < 81 + 16 && i < z.Length; i++) z[i] = 0;
        string mp = p.Length > 8 ? (p[8].Trim().Length == 0 ? "00" : p[8].Trim()) : "00";
        return new Target { Type = CrackType.HANDSHAKE, Essid = es, SsidBytes = esB, ApMac = ap, StaMac = sta, ANonce = aNonce, SNonce = sNonce, Mic = mic, EapolZeroedMic = z, Keyver = keyver, MessagePair = mp, Source = "hc22000" };
    }
}
