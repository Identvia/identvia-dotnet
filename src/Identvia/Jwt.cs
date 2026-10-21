using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Identvia;

internal sealed class CompactJws
{
    public JsonObject Header { get; }
    public JsonObject Payload { get; }
    public byte[] SigningInput { get; }
    public byte[] Signature { get; }

    public CompactJws(string token)
    {
        var p = token.Split('.');
        if (p.Length != 3) throw new IdentviaValidationException("ID token is not a compact JWS.");
        Header = Decode(p[0]); Payload = Decode(p[1]);
        Signature = Base64Url.Decode(p[2]) ?? throw new IdentviaValidationException("ID token is malformed.");
        SigningInput = Encoding.ASCII.GetBytes($"{p[0]}.{p[1]}");
    }

    private static JsonObject Decode(string s) =>
        (Base64Url.Decode(s) is { } b ? JsonExt.ParseObject(Encoding.UTF8.GetString(b)) : null) ?? throw new IdentviaValidationException("ID token is malformed.");
}

internal static class JwsVerifier
{
    public static readonly HashSet<string> Allowed = ["RS256", "ES256"];

    public static bool Verify(CompactJws jws, string alg, JsonObject key)
    {
        if (key.Str("alg") is { } a && a != alg) throw new IdentviaValidationException($"Key {key.Str("kid")} is for {a}, not {alg}.");
        if (key.Str("use") is { } u && u != "sig") throw new IdentviaValidationException("Key is not a signing key.");
        switch (alg)
        {
            case "RS256":
            {
                var n = key.Str("n") is { } ns ? Base64Url.Decode(ns) : null;
                var e = key.Str("e") is { } es ? Base64Url.Decode(es) : null;
                if (key.Str("kty") != "RSA" || n is null || e is null) throw new IdentviaValidationException("RS256 needs an RSA key.");
                if (n.SkipWhile(x => x == 0).Count() * 8 < 2048) throw new IdentviaValidationException("RSA key is shorter than 2048 bits.");
                using var rsa = RSA.Create(new RSAParameters { Modulus = n, Exponent = e });
                return rsa.VerifyData(jws.SigningInput, jws.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            case "ES256":
            {
                var x = key.Str("x") is { } xs ? Base64Url.Decode(xs) : null;
                var y = key.Str("y") is { } ys ? Base64Url.Decode(ys) : null;
                if (key.Str("kty") != "EC" || key.Str("crv") != "P-256" || x?.Length != 32 || y?.Length != 32) throw new IdentviaValidationException("ES256 needs a P-256 key.");
                if (jws.Signature.Length != 64) return false;
                using var ec = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
                return ec.VerifyData(jws.SigningInput, jws.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            default: throw new IdentviaValidationException($"alg {alg} is not allowed.");
        }
    }
}

/// <summary>Caches the JWKS. An unknown kid triggers one refetch, at most every 30 seconds (key rotation).</summary>
internal sealed class JwksCache(Uri url, HttpClient http, TimeProvider time)
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private List<JsonObject>? _keys;
    private DateTimeOffset _last = DateTimeOffset.MinValue;
    public int FetchCount { get; private set; }

    public async Task<JsonObject?> KeyAsync(string? kid, string alg, CancellationToken ct)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_keys is null) await LoadAsync(ct).ConfigureAwait(false);
            if (Find(kid, alg) is { } k) return k;
            if (time.GetUtcNow() - _last < TimeSpan.FromSeconds(30)) return null;
            await LoadAsync(ct).ConfigureAwait(false);
            return Find(kid, alg);
        }
        finally { _lock.Release(); }
    }

    private JsonObject? Find(string? kid, string alg)
    {
        var kty = alg.StartsWith("ES", StringComparison.Ordinal) ? "EC" : "RSA";
        var c = (_keys ?? []).Where(k => k.Str("kty") == kty && (k.Str("use") is null or "sig")).ToList();
        return kid is not null ? c.FirstOrDefault(k => k.Str("kid") == kid) : c.Count == 1 ? c[0] : null;
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        using var res = await http.GetAsync(url, ct).ConfigureAwait(false);
        FetchCount++;
        _last = time.GetUtcNow();
        var o = JsonExt.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        if (!res.IsSuccessStatusCode || o?["keys"] is not JsonArray arr) throw new IdentviaNetworkException($"Could not load the JWKS ({(int)res.StatusCode}).");
        _keys = arr.OfType<JsonObject>().ToList();
    }
}

internal sealed record IdTokenOptions(string Issuer, string ClientId, string? Nonce, int? MaxAge, string? AccessToken, DateTimeOffset Now, TimeSpan Leeway);

/// <summary>OIDC Core §3.1.3.7 ID token validation.</summary>
internal static class IdTokenValidator
{
    public static async Task<JsonObject> ValidateAsync(string token, IdTokenOptions o, Func<string?, string, Task<JsonObject?>> key)
    {
        var jws = new CompactJws(token);
        var alg = jws.Header.Str("alg") ?? throw new IdentviaValidationException("ID token has no alg.");
        if (!JwsVerifier.Allowed.Contains(alg)) throw new IdentviaValidationException($"ID token alg {alg} is not allowed (expected RS256 or ES256; never none or HS*).");
        if (jws.Header.ContainsKey("crit")) throw new IdentviaValidationException("Unsupported crit header.");
        var kid = jws.Header.Str("kid");
        var k = await key(kid, alg).ConfigureAwait(false) ?? throw new IdentviaValidationException($"ID token is signed with an unknown key (kid {kid ?? "none"}).");
        if (!JwsVerifier.Verify(jws, alg, k)) throw new IdentviaValidationException("ID token signature is invalid.");

        var c = jws.Payload;
        if (c.Str("iss") != o.Issuer) throw new IdentviaValidationException($"ID token issuer {c.Str("iss")} is not {o.Issuer}.");
        if (string.IsNullOrEmpty(c.Str("sub"))) throw new IdentviaValidationException("ID token has no sub.");
        var aud = c["aud"] switch
        {
            JsonArray a => a.OfType<JsonValue>().Select(v => v.ToString()).ToList(),
            JsonValue v when c.Str("aud") is { } s => [s],
            _ => new List<string>(),
        };
        if (!aud.Contains(o.ClientId)) throw new IdentviaValidationException("ID token aud does not include this client.");
        var azp = c.Str("azp");
        if (aud.Count > 1 && azp is null) throw new IdentviaValidationException("ID token with several audiences needs azp.");
        if (azp is not null && azp != o.ClientId) throw new IdentviaValidationException("ID token azp is another client.");
        var now = o.Now.ToUnixTimeSeconds();
        var leeway = o.Leeway.TotalSeconds;
        var exp = c.Num("exp") ?? throw new IdentviaValidationException("ID token has no exp.");
        if (now >= exp + leeway) throw new IdentviaValidationException("ID token expired.");
        var iat = c.Num("iat") ?? throw new IdentviaValidationException("ID token has no iat.");
        if (iat > now + leeway) throw new IdentviaValidationException("ID token was issued in the future.");
        if (o.Nonce is not null && (c.Str("nonce") is not { } n || !Util.SafeEquals(n, o.Nonce)))
            throw new IdentviaValidationException("ID token nonce does not match (replay?).");
        if (o.MaxAge is int maxAge)
        {
            var at = c.Num("auth_time") ?? throw new IdentviaValidationException("max_age was requested but auth_time is missing.");
            if (now > at + maxAge + leeway) throw new IdentviaValidationException("auth_time is older than max_age.");
        }
        if (c.Str("at_hash") is { } h && o.AccessToken is not null &&
            !Util.SafeEquals(h, Base64Url.Encode(Util.Sha256(o.AccessToken).AsSpan(0, 16))))
            throw new IdentviaValidationException("ID token at_hash does not match the access token.");
        return c;
    }
}
