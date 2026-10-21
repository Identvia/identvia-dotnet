using System.Security.Cryptography;
using System.Text;

namespace Identvia;

public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[]? Decode(string s)
    {
        foreach (var c in s) if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_')) return null;
        var b = s.Replace('-', '+').Replace('_', '/');
        if (b.Length % 4 == 1) return null;
        b = b.PadRight(b.Length + (4 - b.Length % 4) % 4, '=');
        try { return Convert.FromBase64String(b); } catch (FormatException) { return null; }
    }
}

internal static class Util
{
    public static string RandomToken(int bytes = 32) => Base64Url.Encode(RandomNumberGenerator.GetBytes(bytes));

    public static bool SafeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    public static byte[] Sha256(string s) => SHA256.HashData(Encoding.ASCII.GetBytes(s));

    public static Dictionary<string, string> ParseQuery(string? q)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(q)) return d;
        foreach (var part in q.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var i = part.IndexOf('=');
            var k = Uri.UnescapeDataString((i < 0 ? part : part[..i]).Replace('+', ' '));
            var v = i < 0 ? "" : Uri.UnescapeDataString(part[(i + 1)..].Replace('+', ' '));
            d.TryAdd(k, v);
        }
        return d;
    }

    public static string Query(IEnumerable<KeyValuePair<string, string>> p) =>
        string.Join("&", p.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
}

/// <summary>Proof Key for Code Exchange (RFC 7636), S256 only. Identvia rejects <c>plain</c>.</summary>
public sealed record Pkce(string Verifier, string Challenge)
{
    public string Method => "S256";

    /// <summary>A fresh verifier with 256 bits of entropy (43 chars).</summary>
    public static Pkce Generate() { var v = Util.RandomToken(); return new Pkce(v, ChallengeFor(v)); }

    public static string ChallengeFor(string verifier)
    {
        if (verifier.Length is < 43 or > 128 || !verifier.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'))
            throw new IdentviaConfigurationException("A PKCE verifier must be 43-128 unreserved characters.");
        return Base64Url.Encode(Util.Sha256(verifier));
    }
}
