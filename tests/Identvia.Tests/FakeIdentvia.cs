using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Identvia;

namespace Identvia.Tests;

public static class T
{
    public const string Issuer = "https://id.identvia.test";
    public const string ClientId = "oid_dotnet_test";
    public const string ConfClientId = "oid_dotnet_conf";
    public const string ConfSecret = "ivs_test_secret_value";
    public const string Redirect = "http://127.0.0.1:7890/callback";
    public static readonly RSA SharedRsa = RSA.Create(2048);

    public static string B64(JsonObject o) => Base64Url.Encode(Encoding.UTF8.GetBytes(o.ToJsonString()));

    public static string SignRs256(JsonObject header, JsonObject claims, RSA key)
    {
        var input = $"{B64(header)}.{B64(claims)}";
        return $"{input}.{Base64Url.Encode(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))}";
    }

    public static string SignEs256(JsonObject header, JsonObject claims, ECDsa key)
    {
        var input = $"{B64(header)}.{B64(claims)}";
        return $"{input}.{Base64Url.Encode(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))}";
    }

    public static JsonObject With(this JsonObject o, params (string K, JsonNode? V)[] kv)
    {
        var c = (JsonObject)o.DeepClone();
        foreach (var (k, v) in kv) { if (v is null) c.Remove(k); else c[k] = v; }
        return c;
    }

    public static Dictionary<string, string> Q(string url) => Util.ParseQuery(new Uri(url).Query);
}

/// <summary>An in-memory Identvia that enforces the real server's rules (PKCE S256, nonce, iss, rotation with reuse detection).</summary>
public sealed class FakeIdentvia : HttpMessageHandler
{
    public RSA Rsa = T.SharedRsa;
    public ECDsa? Ec;
    public string Kid = "k1";
    public bool Stage5, WrongIss, OmitIss;
    public string? ForceNonce;
    public int ExpiresIn = 600;
    public Func<JsonObject, string>? IdTokenOverride;
    public List<string> RedirectUris = [T.Redirect, "https://localhost/signin-identvia"];
    public readonly string UserSub = "pw_" + Util.RandomToken(9);
    public readonly HashSet<string> RevokedFamilies = [];
    public readonly List<(string Method, string Path, string Body, string? Auth)> Requests = [];
    public int JwksFetches;
    public int TokenDelayMs;
    public int CibaPolls;
    private readonly Dictionary<string, Dictionary<string, object?>> _codes = [];
    private readonly Dictionary<string, Dictionary<string, object?>> _refresh = [];
    private readonly Dictionary<string, string> _access = [];
    private readonly object _lock = new();

    public HttpClient Client() => new(this) { Timeout = TimeSpan.FromSeconds(10) };

    private JsonObject Discovery()
    {
        var d = new JsonObject
        {
            ["issuer"] = T.Issuer, ["authorization_endpoint"] = $"{T.Issuer}/oauth/authorize", ["token_endpoint"] = $"{T.Issuer}/oauth/token",
            ["userinfo_endpoint"] = $"{T.Issuer}/oauth/userinfo", ["jwks_uri"] = $"{T.Issuer}/oauth/jwks.json", ["revocation_endpoint"] = $"{T.Issuer}/oauth/revoke",
            ["introspection_endpoint"] = $"{T.Issuer}/oauth/introspect", ["end_session_endpoint"] = $"{T.Issuer}/oauth/logout",
            ["response_types_supported"] = new JsonArray("code"), ["subject_types_supported"] = new JsonArray("pairwise"),
            ["id_token_signing_alg_values_supported"] = new JsonArray("RS256"), ["code_challenge_methods_supported"] = new JsonArray("S256"),
            ["authorization_response_iss_parameter_supported"] = true,
            ["grant_types_supported"] = new JsonArray("authorization_code", "refresh_token"),
        };
        if (Stage5)
        {
            d["authorization_details_types_supported"] = new JsonArray("agent_task");
            d["grant_types_supported"] = new JsonArray("authorization_code", "refresh_token", IdentviaServerClient.TokenExchangeGrant, IdentviaServerClient.CibaGrant);
            d["backchannel_authentication_endpoint"] = $"{T.Issuer}/oauth/bc-authorize";
        }
        return d;
    }

    private JsonObject Jwks()
    {
        var p = Rsa.ExportParameters(false);
        var keys = new JsonArray(new JsonObject { ["kty"] = "RSA", ["kid"] = Kid, ["use"] = "sig", ["alg"] = "RS256", ["n"] = Base64Url.Encode(p.Modulus), ["e"] = Base64Url.Encode(p.Exponent) });
        if (Ec is not null)
        {
            var q = Ec.ExportParameters(false).Q;
            keys.Add(new JsonObject { ["kty"] = "EC", ["kid"] = "ec1", ["use"] = "sig", ["alg"] = "ES256", ["crv"] = "P-256", ["x"] = Base64Url.Encode(q.X), ["y"] = Base64Url.Encode(q.Y) });
        }
        return new JsonObject { ["keys"] = keys };
    }

    public string IdToken(string sub, string aud, string? nonce, string at)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var c = new JsonObject
        {
            ["iss"] = T.Issuer, ["sub"] = sub, ["aud"] = aud, ["azp"] = aud, ["iat"] = now, ["exp"] = now + 600, ["auth_time"] = now,
            ["email"] = "ada@example.com", ["email_verified"] = true, ["name"] = "Ada",
            ["at_hash"] = Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(at)).AsSpan(0, 16)),
        };
        if (nonce is not null) c["nonce"] = nonce;
        if (IdTokenOverride is not null) return IdTokenOverride(c);
        return T.SignRs256(new JsonObject { ["alg"] = "RS256", ["kid"] = Kid, ["typ"] = "JWT" }, c, Rsa);
    }

    private JsonObject Issue(string client, string sub, string scope, string? nonce, string? family = null)
    {
        var at = "at_" + Util.RandomToken(18);
        var o = new JsonObject { ["token_type"] = "Bearer", ["access_token"] = at, ["expires_in"] = ExpiresIn, ["scope"] = scope };
        var scopes = scope.Split(' ');
        if (scopes.Contains("openid") && family is null) o["id_token"] = IdToken(sub, client, nonce, at);
        var fam = family ?? "";
        if (scopes.Contains("offline_access"))
        {
            if (fam == "") fam = Util.RandomToken(6);
            var rt = "rt_" + Util.RandomToken(18);
            _refresh[rt] = new() { ["family"] = fam, ["used"] = false, ["sub"] = sub, ["scope"] = scope, ["client"] = client };
            o["refresh_token"] = rt;
        }
        _access[at] = fam;
        return o;
    }

    private static HttpResponseMessage J(int status, JsonObject body) => new((HttpStatusCode)status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
    private static HttpResponseMessage Err(int status, string e, string? d = null) => J(status, d is null ? new() { ["error"] = e } : new() { ["error"] = e, ["error_description"] = d });

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
    {
        var body = r.Content is null ? "" : await r.Content.ReadAsStringAsync(ct);
        if (r.RequestUri!.AbsolutePath == "/oauth/token" && TokenDelayMs > 0) await Task.Delay(TokenDelayMs, ct);
        lock (_lock) return Handle(r, body);
    }

    /// <summary>Client auth like the server: public (client_id only) or confidential (basic or post).</summary>
    private string? Client(HttpRequestMessage r, Dictionary<string, string> f)
    {
        if (r.Headers.Authorization is { Scheme: "Basic" } a)
        {
            var parts = Encoding.UTF8.GetString(Convert.FromBase64String(a.Parameter!)).Split(':', 2).Select(Uri.UnescapeDataString).ToArray();
            return parts[0] == T.ConfClientId && parts[1] == T.ConfSecret ? T.ConfClientId : null;
        }
        if (f.GetValueOrDefault("client_id") == T.ConfClientId) return f.GetValueOrDefault("client_secret") == T.ConfSecret ? T.ConfClientId : null;
        if (f.GetValueOrDefault("client_id") == T.ClientId && !f.ContainsKey("client_secret")) return T.ClientId;
        return null;
    }

    private HttpResponseMessage Handle(HttpRequestMessage r, string body)
    {
        var f = Util.ParseQuery(body);
        var path = r.RequestUri!.AbsolutePath;
        Requests.Add((r.Method.Method, path, body, r.Headers.Authorization?.Scheme));
        switch (path)
        {
            case "/.well-known/openid-configuration": return J(200, Discovery());
            case "/oauth/jwks.json": JwksFetches++; return J(200, Jwks());
            case "/oauth/token":
            {
                var client = Client(r, f);
                if (client is null) return Err(401, "invalid_client");
                switch (f.GetValueOrDefault("grant_type"))
                {
                    case "authorization_code":
                    {
                        if (!_codes.TryGetValue(f.GetValueOrDefault("code") ?? "", out var c) || (bool)c["used"]! || (string)c["client"]! != client) return Err(400, "invalid_grant");
                        c["used"] = true;
                        if ((string)c["redirect_uri"]! != f.GetValueOrDefault("redirect_uri")) return Err(400, "invalid_grant");
                        if (Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(f.GetValueOrDefault("code_verifier") ?? ""))) != (string)c["challenge"]!) return Err(400, "invalid_grant", "PKCE verification failed");
                        var o = Issue(client, (string)c["sub"]!, (string)c["scope"]!, (string?)c["nonce"]);
                        if (c["details"] is string d) o["authorization_details"] = JsonNode.Parse(d);
                        return J(200, o);
                    }
                    case "refresh_token":
                    {
                        if (!_refresh.TryGetValue(f.GetValueOrDefault("refresh_token") ?? "", out var x) || RevokedFamilies.Contains((string)x["family"]!) || (string)x["client"]! != client) return Err(400, "invalid_grant");
                        if ((bool)x["used"]!) { RevokedFamilies.Add((string)x["family"]!); return Err(400, "invalid_grant", "Refresh token reuse detected"); }
                        x["used"] = true;
                        return J(200, Issue(client, (string)x["sub"]!, (string)x["scope"]!, null, (string)x["family"]!));
                    }
                    case IdentviaServerClient.TokenExchangeGrant when Stage5:
                    {
                        if (client != T.ConfClientId) return Err(400, "unauthorized_client");
                        if (!_access.ContainsKey(f.GetValueOrDefault("subject_token") ?? "")) return Err(400, "invalid_grant");
                        var at = "at_x_" + Util.RandomToken(12);
                        _access[at] = "x";
                        return J(200, new() { ["access_token"] = at, ["token_type"] = "Bearer", ["expires_in"] = 300, ["issued_token_type"] = IdentviaServerClient.AccessTokenType, ["scope"] = f.GetValueOrDefault("scope") ?? "" });
                    }
                    case IdentviaServerClient.CibaGrant when Stage5:
                        if (f.GetValueOrDefault("auth_req_id") != "ciba_1") return Err(400, "invalid_grant");
                        return ++CibaPolls < 2 ? Err(400, "authorization_pending") : J(200, Issue(client, UserSub, "openid", null));
                }
                return Err(400, "unsupported_grant_type");
            }
            case "/oauth/bc-authorize" when Stage5:
                if (Client(r, f) != T.ConfClientId) return Err(401, "invalid_client");
                return J(200, new() { ["auth_req_id"] = "ciba_1", ["expires_in"] = 300, ["interval"] = 1 });
            case "/oauth/userinfo":
            {
                var at = r.Headers.Authorization?.Parameter ?? "";
                if (!_access.TryGetValue(at, out var fam) || RevokedFamilies.Contains(fam)) return Err(401, "invalid_token");
                return J(200, new() { ["sub"] = UserSub, ["email"] = "ada@example.com" });
            }
            case "/oauth/introspect":
            {
                if (Client(r, f) != T.ConfClientId) return Err(401, "invalid_client");
                var active = _access.TryGetValue(f.GetValueOrDefault("token") ?? "", out var fam) && !RevokedFamilies.Contains(fam);
                return J(200, active ? new() { ["active"] = true, ["sub"] = UserSub, ["client_id"] = T.ClientId } : new() { ["active"] = false });
            }
            case "/oauth/revoke":
                if (_refresh.TryGetValue(f.GetValueOrDefault("token") ?? "", out var rr)) RevokedFamilies.Add((string)rr["family"]!);
                return new HttpResponseMessage(HttpStatusCode.OK);
        }
        return Err(404, "not_found");
    }

    /// <summary>The user signs in and approves; returns the redirect Identvia would send.</summary>
    public string Authorize(string url, bool deny = false)
    {
        lock (_lock)
        {
            var q = T.Q(url);
            var ru = q["redirect_uri"];
            if (!RedirectUris.Contains(ru)) throw new InvalidOperationException("Invalid redirect " + ru);
            if (q.GetValueOrDefault("code_challenge_method") != "S256" || !q.ContainsKey("nonce") || !q.ContainsKey("state")) throw new InvalidOperationException("bad request");
            var p = new List<KeyValuePair<string, string>> { new("state", q["state"]) };
            if (!OmitIss) p.Add(new("iss", WrongIss ? "https://evil.example" : T.Issuer));
            if (deny) { p.Add(new("error", "access_denied")); p.Add(new("error_description", "The user denied access")); }
            else
            {
                var code = "c_" + Util.RandomToken(18);
                _codes[code] = new()
                {
                    ["challenge"] = q["code_challenge"], ["redirect_uri"] = ru, ["nonce"] = ForceNonce ?? q["nonce"], ["scope"] = q["scope"],
                    ["sub"] = UserSub, ["used"] = false, ["client"] = q["client_id"], ["details"] = q.GetValueOrDefault("authorization_details"),
                };
                p.Add(new("code", code));
            }
            return ru + "?" + Util.Query(p);
        }
    }
}

public sealed class FakeBrowser(FakeIdentvia idp) : IAuthBrowser
{
    public bool Deny, Cancel;
    public Func<string, string>? Tamper;
    public readonly List<Uri> Opened = [];

    public Task<Uri> AuthenticateAsync(Uri url, Uri redirectUri, CancellationToken ct)
    {
        Opened.Add(url);
        if (Cancel) throw new IdentviaCancelledException();
        if (url.AbsolutePath == "/oauth/logout") return Task.FromResult(redirectUri);
        var cb = idp.Authorize(url.AbsoluteUri, Deny);
        return Task.FromResult(new Uri(Tamper?.Invoke(cb) ?? cb));
    }
}
