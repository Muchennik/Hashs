using System.Linq;

namespace WifiCracker;

public enum CrackType { PMKID, HANDSHAKE }

public class Target
{
    public CrackType Type;
    public string Essid = "";
    public byte[] SsidBytes = System.Array.Empty<byte>();
    public byte[] ApMac = System.Array.Empty<byte>();
    public byte[] StaMac = System.Array.Empty<byte>();
    public byte[]? Pmkid, ANonce, SNonce, Mic, EapolZeroedMic;
    public int Keyver = 2;
    public string MessagePair = "00";
    public long AddedAt = System.DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public string Source = "";

    public string Id => $"{Type}_{Hex.Encode(ApMac)}_{Hex.Encode(StaMac)}_{Hex.Encode(SsidBytes)}";
    public string ApMacStr => Mac(ApMac);
    public string TypeStr => Type == CrackType.PMKID ? "PMKID" : "HANDSHAKE";
    public static string Mac(byte[] b) => string.Join(":", b.Select(x => x.ToString("x2")));
}

public class Cracked
{
    public string Essid = "", ApMac = "", Type = "", Password = "";
    public long FoundAt = System.DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
