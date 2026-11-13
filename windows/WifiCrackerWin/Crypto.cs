using System;
using System.Security.Cryptography;
using System.Text;

namespace WifiCracker;

/// WPA/WPA2-PSK crypto: PBKDF2, PMK, PMKID, KCK, MIC (keyver 1/2/3).
public static class Crypto
{
    public static byte[] HmacSha1(byte[] key, byte[] msg) { using var h = new HMACSHA1(key); return h.ComputeHash(msg); }
    public static byte[] HmacMd5(byte[] key, byte[] msg) { using var h = new HMACMD5(key); return h.ComputeHash(msg); }

    /// PMK = PBKDF2-HMAC-SHA1(passphrase UTF-8, ssid, 4096, 32) — нативно (.NET).
    public static byte[] Pmk(string passphrase, byte[] ssid)
    {
        using var k = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(passphrase), ssid, 4096, HashAlgorithmName.SHA1);
        return k.GetBytes(32);
    }

    public static byte[] Pmkid(byte[] pmk, byte[] apMac, byte[] staMac)
    {
        var msg = Concat(Encoding.ASCII.GetBytes("PMK Name"), apMac, staMac);
        var full = HmacSha1(pmk, msg);
        var o = new byte[16]; Array.Copy(full, o, 16); return o;
    }

    public static byte[] Kck(byte[] pmk, byte[] apMac, byte[] staMac, byte[] aNonce, byte[] sNonce)
    {
        var a = Encoding.ASCII.GetBytes("Pairwise key expansion");
        var b = Concat(MinMax(apMac, staMac), MinMax(aNonce, sNonce));
        var input = Concat(a, new byte[] { 0 }, b, new byte[] { 0 });
        var r = HmacSha1(pmk, input);
        var kck = new byte[16]; Array.Copy(r, kck, 16); return kck;
    }

    public static byte[] Mic(int keyver, byte[] kck, byte[] eapolZeroed) => keyver switch
    {
        1 => HmacMd5(kck, eapolZeroed),
        3 => Take16(AesCmac(kck, eapolZeroed)),
        _ => Take16(HmacSha1(kck, eapolZeroed)),
    };

    static byte[] Take16(byte[] x) { var o = new byte[16]; Array.Copy(x, o, 16); return o; }
    static byte[] Concat(params byte[][] arrs)
    {
        int n = 0; foreach (var a in arrs) n += a.Length;
        var o = new byte[n]; int p = 0; foreach (var a in arrs) { Array.Copy(a, 0, o, p, a.Length); p += a.Length; } return o;
    }
    static byte[] MinMax(byte[] x, byte[] y) => Cmp(x, y) <= 0 ? Concat(x, y) : Concat(y, x);
    static int Cmp(byte[] x, byte[] y)
    {
        for (int i = 0; i < x.Length; i++) { int a = x[i], b = y[i]; if (a != b) return a - b; } return 0;
    }

    // AES-CMAC (RFC 4493) для keyver 3
    static byte[] AesCmac(byte[] key, byte[] msg)
    {
        using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
        using var enc = aes.CreateEncryptor();
        byte[] E(byte[] b) { var o = new byte[16]; enc.TransformBlock(b, 0, 16, o, 0); return o; }
        var L = E(new byte[16]);
        var k1 = Dbl(L); var k2 = Dbl(k1);
        int n = (msg.Length + 15) / 16;
        bool complete = msg.Length > 0 && msg.Length % 16 == 0;
        byte[] last;
        if (complete) last = Xor(Slice(msg, (n - 1) * 16, 16), k1);
        else
        {
            var padded = new byte[16];
            int start = n == 0 ? 0 : (n - 1) * 16;
            int len = msg.Length - start;
            Array.Copy(msg, start, padded, 0, len);
            padded[len] = 0x80;
            last = Xor(padded, k2);
        }
        var x = new byte[16];
        int blocks = n == 0 ? 0 : n - 1;
        for (int i = 0; i < blocks; i++) x = E(Xor(x, Slice(msg, i * 16, 16)));
        return E(Xor(last, x));
    }
    static byte[] Dbl(byte[] b)
    {
        var r = new byte[16]; int carry = 0;
        for (int i = 15; i >= 0; i--) { int v = (b[i] << 1) | carry; r[i] = (byte)v; carry = (v >> 8) & 1; }
        if ((b[0] & 0x80) != 0) r[15] ^= 0x87; return r;
    }
    static byte[] Xor(byte[] a, byte[] b) { var r = new byte[a.Length]; for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]); return r; }
    static byte[] Slice(byte[] a, int off, int len) { var o = new byte[len]; Array.Copy(a, off, o, 0, len); return o; }
}
