using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Identvia;

/// <summary>
/// Opens the authorization URL in a <b>system</b> browser and returns the URL Identvia redirected to.
/// Throw <see cref="IdentviaCancelledException"/> when the user gives up. Never use an embedded web view (RFC 8252 §8.12).
/// </summary>
public interface IAuthBrowser
{
    Task<Uri> AuthenticateAsync(Uri url, Uri redirectUri, CancellationToken ct);
}

/// <summary>Secure storage for the session.</summary>
public interface ITokenStore
{
    Task<string?> GetAsync(string key);
    Task SetAsync(string key, string value);
    Task DeleteAsync(string key);
}

/// <summary>For tests and short-lived tools. Not persistent.</summary>
public sealed class InMemoryTokenStore : ITokenStore
{
    public ConcurrentDictionary<string, string> Values { get; } = new();
    public Task<string?> GetAsync(string key) => Task.FromResult(Values.TryGetValue(key, out var v) ? v : null);
    public Task SetAsync(string key, string value) { Values[key] = value; return Task.CompletedTask; }
    public Task DeleteAsync(string key) { Values.TryRemove(key, out _); return Task.CompletedTask; }
}

/// <summary>
/// Windows (WPF, WinUI, WinForms, MAUI on Windows): each value is encrypted with DPAPI for the current user and stored under
/// %LOCALAPPDATA%\Identvia\&lt;app&gt;. On MAUI for Android/iOS/macOS, write a small ITokenStore over <c>SecureStorage.Default</c> instead.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiTokenStore(string appName) : ITokenStore
{
    private readonly string _dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Identvia", Safe(appName));
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Identvia.TokenStore.v1");

    private static string Safe(string s) => string.Concat(s.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_'));
    private string PathFor(string key) => Path.Combine(_dir, Safe(key) + ".bin");

    public async Task<string?> GetAsync(string key)
    {
        var p = PathFor(key);
        if (!File.Exists(p)) return null;
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(await File.ReadAllBytesAsync(p).ConfigureAwait(false), Entropy, DataProtectionScope.CurrentUser)); }
        catch (CryptographicException) { File.Delete(p); return null; }
    }

    public async Task SetAsync(string key, string value)
    {
        Directory.CreateDirectory(_dir);
        await File.WriteAllBytesAsync(PathFor(key), ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.CurrentUser)).ConfigureAwait(false);
    }

    public Task DeleteAsync(string key) { File.Delete(PathFor(key)); return Task.CompletedTask; }
}
