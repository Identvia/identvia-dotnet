using System.Text.RegularExpressions;

namespace Identvia;

public static partial class RedirectUri
{
    internal static readonly HashSet<string> Loopback = new(StringComparer.OrdinalIgnoreCase) { "localhost", "127.0.0.1", "[::1]", "::1" };

    [GeneratedRegex(@"^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$")]
    private static partial Regex ReverseDomain();

    /// <summary>
    /// Checks a native-app redirect URI (RFC 8252): <c>http://127.0.0.1:port/path</c> (loopback, for desktop),
    /// a claimed <c>https://</c> URL, or a reverse-domain private-use scheme such as <c>com.example.app:/oauth/identvia</c>.
    /// </summary>
    public static Uri Validate(string s)
    {
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u)) throw new IdentviaConfigurationException($"redirectUri is not a valid URI: {s}");
        if (u.Fragment.Length > 0) throw new IdentviaConfigurationException("redirectUri must not contain a fragment.");
        var scheme = u.Scheme.ToLowerInvariant();
        if (scheme == "https" && u.Host.Length > 0) return u;
        if (scheme == "http" && Loopback.Contains(u.Host)) return u;
        if (scheme is not ("http" or "https" or "file" or "javascript" or "data") && ReverseDomain().IsMatch(scheme)) return u;
        throw new IdentviaConfigurationException($"redirectUri must be http://127.0.0.1:port/…, https://, or a reverse-domain scheme such as com.example.app:/callback (RFC 8252). Got {s}");
    }

    /// <summary>True when <paramref name="callback"/> was sent to <paramref name="registered"/>: same scheme, host, port and path.</summary>
    public static bool Matches(Uri callback, Uri registered) =>
        string.Equals(callback.Scheme, registered.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(callback.Host, registered.Host, StringComparison.OrdinalIgnoreCase) &&
        callback.Port == registered.Port &&
        callback.AbsolutePath == registered.AbsolutePath;

    internal static string NormalizeIssuer(string s)
    {
        var i = s.Trim().TrimEnd('/');
        if (!Uri.TryCreate(i, UriKind.Absolute, out var u) || u.Query.Length > 0 || u.Fragment.Length > 0 ||
            !(u.Scheme == "https" || (u.Scheme == "http" && Loopback.Contains(u.Host))))
            throw new IdentviaConfigurationException("issuer must be an https:// URL without query or fragment.");
        return i;
    }
}
