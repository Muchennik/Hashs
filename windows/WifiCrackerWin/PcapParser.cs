using System;
using System.Collections.Generic;
using System.Text;

namespace WifiCracker;

/// .cap/.pcap + .pcapng: beacon SSID + EAPOL M1/M2 -> Target (PMKID, handshake).
public static class PcapParser
{
    class Hs { public byte[]? ANonce, SNonce, Mic, EapolZeroed, Pmkid, Ap, Sta; public int Keyver = 2; }

    public static List<Target> Parse(byte[] b)
    {
        var ssidByBssid = new Dictionary<string, (string, byte[])>();
        var hsByKey = new Dictionary<string, Hs>();
        var frames = (b.Length >= 4 && Le32(b, 0) == 0x0A0D0D0AL) ? PcapngFrames(b) : PcapFrames(b);
        foreach (var (lt, pkt) in frames)
        { try { Handle80211(Dot11(lt, pkt), ssidByBssid, hsByKey); } catch { } }

        var outp = new List<Target>();
        foreach (var kv in hsByKey)
        {
            var hs = kv.Value;
            if (hs.Ap == null || hs.Sta == null) continue;
            if (!ssidByBssid.TryGetValue(Target.Mac(hs.Ap), out var sb)) continue;
            var (es, esB) = sb;
            if (hs.Pmkid != null)
                outp.Add(new Target { Type = CrackType.PMKID, Essid = es, SsidBytes = esB, ApMac = hs.Ap, StaMac = hs.Sta, Pmkid = hs.Pmkid, Source = "cap" });
            if (hs.ANonce != null && hs.SNonce != null && hs.Mic != null && hs.EapolZeroed != null)
                outp.Add(new Target { Type = CrackType.HANDSHAKE, Essid = es, SsidBytes = esB, ApMac = hs.Ap, StaMac = hs.Sta, ANonce = hs.ANonce, SNonce = hs.SNonce, Mic = hs.Mic, EapolZeroedMic = hs.EapolZeroed, Keyver = hs.Keyver, Source = "cap" });
        }
        return outp;
    }

    static List<(int, byte[])> PcapFrames(byte[] b)
    {
        var res = new List<(int, byte[])>();
        long magic = U32(b, 0);
        bool le = magic == 0xA1B2C3D4L || magic == 0xA1B23C4DL;
        int linktype = (int)(le ? Le32(b, 20) : Be32(b, 20));
        int off = 24;
        while (off + 16 <= b.Length)
        {
            int inclLen = (int)(le ? Le32(b, off + 8) : Be32(b, off + 8));
            off += 16;
            if (inclLen < 0 || off + inclLen > b.Length) break;
            res.Add((linktype, Sub(b, off, inclLen)));
            off += inclLen;
        }
        return res;
    }
    static List<(int, byte[])> PcapngFrames(byte[] b)
    {
        var res = new List<(int, byte[])>();
        int off = 0, linktype = 127;
        while (off + 12 <= b.Length)
        {
            int btype = (int)Le32(b, off); int blen = (int)Le32(b, off + 4);
            if (blen < 12 || off + blen > b.Length) break;
            if (btype == 0x00000001) linktype = (int)(Le32(b, off + 8) & 0xffff);
            else if (btype == 0x00000006)
            {
                int capLen = (int)Le32(b, off + 20); int start = off + 28;
                if (start + capLen <= b.Length) res.Add((linktype, Sub(b, start, capLen)));
            }
            else if (btype == 0x00000003)
            {
                int start = off + 12; int capLen = blen - 16;
                if (capLen > 0 && start + capLen <= b.Length) res.Add((linktype, Sub(b, start, capLen)));
            }
            off += blen;
        }
        return res;
    }
    static byte[] Dot11(int lt, byte[] pkt)
    {
        if (lt == 127) { int itlen = (pkt[2] & 0xff) | ((pkt[3] & 0xff) << 8); return Sub(pkt, itlen, pkt.Length - itlen); }
        return pkt;
    }

    static void Handle80211(byte[] f, Dictionary<string, (string, byte[])> ssids, Dictionary<string, Hs> hs)
    {
        if (f.Length < 24) return;
        int fc0 = f[0] & 0xff, fc1 = f[1] & 0xff;
        int type = (fc0 >> 2) & 3, subtype = (fc0 >> 4) & 0xf;
        int toDS = fc1 & 1, fromDS = (fc1 >> 1) & 1;

        if (type == 0 && (subtype == 8 || subtype == 5))
        {
            var bssid = Sub(f, 16, 6);
            int p = 24 + 12;
            while (p + 2 <= f.Length)
            {
                int tag = f[p] & 0xff, len = f[p + 1] & 0xff;
                if (p + 2 + len > f.Length) break;
                if (tag == 0 && len > 0) { var sb = Sub(f, p + 2, len); ssids[Target.Mac(bssid)] = (Encoding.UTF8.GetString(sb), sb); }
                p += 2 + len;
            }
            return;
        }
        if (type != 2) return;
        int hdr = 24;
        if (toDS == 1 && fromDS == 1) hdr += 6;
        if ((subtype & 0x8) != 0) hdr += 2;
        if (hdr + 8 > f.Length) return;
        if ((f[hdr] & 0xff) != 0xAA || (f[hdr + 6] & 0xff) != 0x88 || (f[hdr + 7] & 0xff) != 0x8E) return;
        var eapol = Sub(f, hdr + 8, f.Length - (hdr + 8));
        var addr1 = Sub(f, 4, 6); var addr2 = Sub(f, 10, 6);
        byte[] ap, sta;
        if (fromDS == 1) { ap = addr2; sta = addr1; } else { ap = addr1; sta = addr2; }
        ParseEapol(eapol, ap, sta, hs);
    }

    static void ParseEapol(byte[] e, byte[] ap, byte[] sta, Dictionary<string, Hs> map)
    {
        if (e.Length < 95 || (e[1] & 0xff) != 3) return;
        int bodyLen = ((e[2] & 0xff) << 8) | (e[3] & 0xff);
        int total = 4 + bodyLen;
        if (total > e.Length) return;
        int keyInfo = ((e[5] & 0xff) << 8) | (e[6] & 0xff);
        int keyver = keyInfo & 0x07;
        bool mic = (keyInfo & 0x100) != 0;
        bool ack = (keyInfo & 0x080) != 0;
        var nonce = Sub(e, 17, 32);
        string key = Target.Mac(ap) + "|" + Target.Mac(sta);
        if (!map.TryGetValue(key, out var hs)) { hs = new Hs { Ap = ap, Sta = sta }; map[key] = hs; }

        if (ack && !mic)
        {
            hs.ANonce = nonce;
            if (e.Length >= 97)
            {
                int kdl = ((e[95] & 0xff) << 8) | (e[96] & 0xff);
                if (97 + kdl <= e.Length) hs.Pmkid = FindPmkid(Sub(e, 97, kdl));
            }
        }
        else if (mic)
        {
            hs.SNonce = nonce;
            hs.Mic = Sub(e, 81, 16);
            hs.Keyver = keyver;
            var z = Sub(e, 0, total);
            for (int i = 81; i < 81 + 16 && i < z.Length; i++) z[i] = 0;
            hs.EapolZeroed = z;
        }
    }

    static byte[]? FindPmkid(byte[] kd)
    {
        int i = 0;
        while (i + 2 <= kd.Length)
        {
            int id = kd[i] & 0xff, len = kd[i + 1] & 0xff;
            if (id == 0xdd && len >= 20 && i + 2 + len <= kd.Length)
                if ((kd[i + 2] & 0xff) == 0x00 && (kd[i + 3] & 0xff) == 0x0F && (kd[i + 4] & 0xff) == 0xAC && (kd[i + 5] & 0xff) == 0x04)
                    return Sub(kd, i + 6, 16);
            if (len == 0) break;
            i += 2 + len;
        }
        return null;
    }

    static byte[] Sub(byte[] a, int off, int len) { var o = new byte[len]; Array.Copy(a, off, o, 0, len); return o; }
    static long U32(byte[] b, int o) => Le32(b, o);
    static long Le32(byte[] b, int o) => (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8) | ((b[o + 2] & 0xffL) << 16) | ((b[o + 3] & 0xffL) << 24);
    static long Be32(byte[] b, int o) => ((b[o] & 0xffL) << 24) | ((b[o + 1] & 0xffL) << 16) | ((b[o + 2] & 0xffL) << 8) | (b[o + 3] & 0xffL);
}
