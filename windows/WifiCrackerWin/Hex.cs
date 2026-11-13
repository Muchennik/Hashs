using System;
using System.Linq;
using System.Text;

namespace WifiCracker;

public static class Hex
{
    public static byte[] Decode(string s)
    {
        var c = new string(s.Trim().Where(ch => !char.IsWhiteSpace(ch) && ch != ':' && ch != '-').ToArray());
        if (c.Length % 2 != 0) throw new ArgumentException("odd hex length");
        var outp = new byte[c.Length / 2];
        for (int i = 0; i < c.Length; i += 2)
            outp[i / 2] = (byte)((Hv(c[i]) << 4) | Hv(c[i + 1]));
        return outp;
    }
    static int Hv(char ch) => ch switch
    {
        >= '0' and <= '9' => ch - '0',
        >= 'a' and <= 'f' => ch - 'a' + 10,
        >= 'A' and <= 'F' => ch - 'A' + 10,
        _ => throw new ArgumentException("not hex: " + ch)
    };
    public static string Encode(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
}
