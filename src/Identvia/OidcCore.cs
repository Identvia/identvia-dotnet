using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Identvia;

/// <summary>Discovery, JWKS and token-endpoint calls shared by the public and server clients.</summary>
internal sealed class OidcCore(string issuer, string clientId, string? clientSecret, HttpClient http, TimeProvider time)
{
    public string Issuer { get; } = RedirectUri.NormalizeIssuer(issuer);
    public string ClientId { get; } = string.IsNullOrWhiteSpace(clientId) ? throw new IdentviaConfigurationException("ClientId is required.") : clientId;
    public HttpClient Http => http;
    public TimeProvider Time => time;
    private readonly SemaphoreSlim _metaLock = new(1, 1);
    private ProviderMetadata? _meta;
    public JwksCache? Jwks { get; private set; }

    public async Task<ProviderMetadata> DiscoveryAsync(CancellationToken ct = default)
    {
        if (_meta is not null) return _meta;
        await _metaLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_meta is not null) return _meta;
            using var res = await http.GetAsync($"{Issuer}/.well-known/openid-configuration", ct).ConfigureAwait(false);
            var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            ProviderMetadata? m = null;
            try { if (res.IsSuccessStatusCode) m = JsonSerializer.Deserialize(body, IdentviaJson.Default.ProviderMetadata); } catch (JsonException) { }
            if (m is null) throw new IdentviaNetworkException($"Discovery failed ({(int)res.StatusCode}).");
            if (m.Issuer != Issuer) throw new IdentviaValidationException($"Discovery issuer {m.Issuer} is not {Issuer}.");
            if (m.CodeChallengeMethodsSupported is { } c && !c.Contains("S256")) throw new IdentviaUnsupportedException("Server does not support PKCE S256.");
            Jwks = new JwksCache(Endpoint(m.JwksUri), http, time);
            return _meta = m;
        }
        finally { _metaLock.Release(); }
    }

    public static Uri Endpoint(string? s)
    {
        if (s is null || !Uri.TryCreate(s, UriKind.Absolute, out var u) || !(u.Scheme == "https" || (u.Scheme == "http" && RedirectUri.Loopback.Contains(u.Host))))
            throw new IdentviaUnsupportedException($"Endpoint missing or not https: {s ?? "none"}");
        return u;
    }

    public async Task<JsonObject> ValidateIdTokenAsync(string token, string? nonce, int? maxAge, string? accessToken, CancellationToken ct)
    {
        await DiscoveryAsync(ct).ConfigureAwait(false);
        var jwks = Jwks!;
        return await IdTokenValidator.ValidateAsync(token, new IdTokenOptions(Issuer, ClientId, nonce, maxAge, accessToken, time.GetUtcNow(), TimeSpan.FromSeconds(60)),
            (kid, alg) => jwks.KeyAsync(kid, alg, ct)).ConfigureAwait(false);
    }

    /// <summary>POSTs a form to an endpoint, authenticating as the client (client_secret_basic if a secret is set, else client_id).</summary>
    public async Task<(int Status, JsonObject? Body)> PostFormAsync(Uri url, IEnumerable<KeyValuePair<string, string>> fields, CancellationToken ct)
    {
        var f = fields.ToList();
        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        if (clientSecret is not null)
        {
            // RFC 6749 §2.3.1: form-urlencode id and secret before base64.
            var cred = $"{Uri.EscapeDataString(ClientId)}:{Uri.EscapeDataString(clientSecret)}";
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(cred)));
        }
        else f.Add(new("client_id", ClientId));
        req.Content = new FormUrlEncodedContent(f);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        HttpResponseMessage res;
        try { res = await http.SendAsync(req, ct).ConfigureAwait(false); }
        catch (HttpRequestException e) { throw new IdentviaNetworkException(e.Message, e); }
        using (res)
        {
            var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ((int)res.StatusCode, JsonExt.ParseObject(body));
        }
    }

    public async Task<TokenSet> TokenRequestAsync(IEnumerable<KeyValuePair<string, string>> fields, CancellationToken ct)
    {
        var m = await DiscoveryAsync(ct).ConfigureAwait(false);
        var (status, o) = await PostFormAsync(Endpoint(m.TokenEndpoint), fields, ct).ConfigureAwait(false);
        if (o is null) throw new IdentviaNetworkException($"Token endpoint returned invalid JSON ({status}).");
        if (status != 200) throw new IdentviaTokenException(o.Str("error") ?? $"http_{status}", o.Str("error_description"), status);
        return ParseTokens(o);
    }

    public TokenSet ParseTokens(JsonObject o)
    {
        var at = o.Str("access_token");
        if (at is null || !string.Equals(o.Str("token_type"), "bearer", StringComparison.OrdinalIgnoreCase) && o.Str("token_type") != "N_A")
            throw new IdentviaValidationException("Token response has no Bearer access_token.");
        return new TokenSet
        {
            AccessToken = at, ExpiresAt = time.GetUtcNow().AddSeconds(o.Num("expires_in") ?? 600),
            RefreshToken = o.Str("refresh_token"), IdToken = o.Str("id_token"), Scope = o.Str("scope"),
            AuthorizationDetails = o["authorization_details"]?.DeepClone() as JsonArray, IssuedTokenType = o.Str("issued_token_type"),
        };
    }
}
