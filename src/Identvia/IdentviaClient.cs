using System.Text.Json;

namespace Identvia;

public sealed class IdentviaClientOptions
{
    public string Issuer { get; set; } = IdentviaDefaults.Issuer;
    public required string ClientId { get; set; }
    /// <summary>For desktop: <c>http://127.0.0.1:PORT/callback</c>. For MAUI mobile: <c>com.example.app:/oauth/identvia</c>.</summary>
    public required string RedirectUri { get; set; }
    public IList<string> Scopes { get; set; } = ["email", "profile", "offline_access"];
    /// <summary>Refresh this long before the access token expires.</summary>
    public TimeSpan RefreshLeeway { get; set; } = TimeSpan.FromSeconds(60);
    public HttpClient? HttpClient { get; set; }
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}

public static class IdentviaDefaults
{
    public const string Issuer = "https://id.identvia.com";
    public const string AuthenticationScheme = "Identvia";
    public const string DisplayName = "Identvia";
}

/// <summary>
/// Sign in with Identvia from a native app (WPF, WinUI, WinForms, MAUI, console). It's a <b>public client</b>: there's no secret,
/// because anything shipped in an app can be extracted. It runs the authorization code flow with PKCE S256 in the system browser,
/// validates the ID token, stores the session and rotates refresh tokens.
/// </summary>
public sealed class IdentviaClient : IDisposable
{
    private readonly OidcCore _core;
    private readonly IAuthBrowser _browser;
    private readonly ITokenStore _store;
    private readonly IdentviaClientOptions _o;
    private readonly bool _ownsHttp;
    private readonly SemaphoreSlim _sessionLock = new(1, 1);
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private Task<IdentviaSession>? _refreshing;
    private IdentviaSession? _session;
    private bool _loaded;
    private int _signingIn;

    public IdentviaClient(IdentviaClientOptions options, IAuthBrowser browser, ITokenStore store)
    {
        _o = options;
        _ownsHttp = options.HttpClient is null;
        _core = new OidcCore(options.Issuer, options.ClientId, null, options.HttpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) }, options.TimeProvider);
        RedirectUri = Identvia.RedirectUri.Validate(options.RedirectUri);
        Scopes = new[] { "openid" }.Concat(options.Scopes).Distinct().ToList();
        _browser = browser;
        _store = store;
    }

    public string Issuer => _core.Issuer;
    public string ClientId => _core.ClientId;
    public Uri RedirectUri { get; }
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>Raised on sign-in, refresh and sign-out.</summary>
    public event EventHandler<IdentviaSession?>? SessionChanged;

    public Task<ProviderMetadata> GetDiscoveryAsync(CancellationToken ct = default) => _core.DiscoveryAsync(ct);

    /// <summary>Builds the authorization URL. Use with <see cref="CompleteAuthorizationAsync"/> if you open the browser yourself.</summary>
    public async Task<(Uri Url, AuthorizationTransaction Transaction)> CreateAuthorizationRequestAsync(SignInOptions? opts = null, CancellationToken ct = default)
    {
        opts ??= new();
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        var pkce = Pkce.Generate();
        var tx = new AuthorizationTransaction(Util.RandomToken(), Util.RandomToken(), pkce.Verifier, RedirectUri.AbsoluteUri, opts.MaxAge);
        var q = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"), new("client_id", ClientId), new("redirect_uri", tx.RedirectUri),
            new("scope", string.Join(' ', Scopes.Concat(opts.Scopes ?? []).Distinct())),
            new("state", tx.State), new("nonce", tx.Nonce), new("code_challenge", pkce.Challenge), new("code_challenge_method", "S256"),
        };
        if (opts.Prompt is { } p) q.Add(new("prompt", p));
        if (opts.MaxAge is { } ma) q.Add(new("max_age", ma.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        if (opts.LoginHint is { } lh) q.Add(new("login_hint", lh));
        if (opts.UiLocales is { Count: > 0 } ul) q.Add(new("ui_locales", string.Join(' ', ul)));
        if (opts.AuthorizationDetails is { Count: > 0 } ad)
        {
            var supported = m.AuthorizationDetailsTypesSupported ?? [];
            if (ad.FirstOrDefault(d => !supported.Contains(d.Type)) is { } bad)
                throw new IdentviaUnsupportedException($"authorization_details type {bad.Type} needs server 2026-10-21_5+ (not advertised in discovery).");
            q.Add(new("authorization_details", AuthorizationDetail.Encode(ad)));
        }
        var b = OidcCore.Endpoint(m.AuthorizationEndpoint).AbsoluteUri;
        return (new Uri(b + (b.Contains('?') ? "&" : "?") + Util.Query(q)), tx);
    }

    /// <summary>Checks the redirect (URI, state, RFC 9207 iss), redeems the code and validates the ID token.</summary>
    public async Task<IdentviaSession> CompleteAuthorizationAsync(Uri callback, AuthorizationTransaction tx, CancellationToken ct = default)
    {
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        if (!Identvia.RedirectUri.Matches(callback, new Uri(tx.RedirectUri))) throw new IdentviaInvalidStateException("The callback is not this app's redirect URI.");
        var p = Util.ParseQuery(callback.Query);
        if (!p.TryGetValue("state", out var state) || !Util.SafeEquals(state, tx.State)) throw new IdentviaInvalidStateException("state does not match this sign-in.");
        if (p.TryGetValue("iss", out var iss)) { if (iss != Issuer) throw new IdentviaInvalidStateException($"iss {iss} is not {Issuer} (mix-up attack?)."); }
        else if (m.AuthorizationResponseIssParameterSupported) throw new IdentviaInvalidStateException("iss is missing from the authorization response.");
        if (p.TryGetValue("error", out var err)) throw new IdentviaAuthorizationException(err, p.GetValueOrDefault("error_description"));
        if (!p.TryGetValue("code", out var code)) throw new IdentviaInvalidStateException("No code in the authorization response.");
        var t = await _core.TokenRequestAsync([new("grant_type", "authorization_code"), new("code", code), new("redirect_uri", tx.RedirectUri), new("code_verifier", tx.CodeVerifier)], ct).ConfigureAwait(false);
        var idToken = t.IdToken ?? throw new IdentviaValidationException("The token response has no id_token.");
        var claims = await _core.ValidateIdTokenAsync(idToken, tx.Nonce, tx.MaxAge, t.AccessToken, ct).ConfigureAwait(false);
        return new IdentviaSession(IdentviaUser.From(claims), t);
    }

    /// <summary>Opens the system browser, signs the user in and stores the session.</summary>
    public async Task<IdentviaSession> SignInAsync(SignInOptions? options = null, CancellationToken ct = default)
    {
        if (Interlocked.Exchange(ref _signingIn, 1) == 1) throw new IdentviaConfigurationException("A sign-in is already in progress.");
        try
        {
            var (url, tx) = await CreateAuthorizationRequestAsync(options, ct).ConfigureAwait(false);
            var back = await _browser.AuthenticateAsync(url, RedirectUri, ct).ConfigureAwait(false);
            var s = await CompleteAuthorizationAsync(back, tx, ct).ConfigureAwait(false);
            await SaveAsync(s).ConfigureAwait(false);
            return s;
        }
        finally { Volatile.Write(ref _signingIn, 0); }
    }

    private string Key(string n) => $"identvia.{ClientId}.{n}";

    /// <summary>The stored session, if any. No network.</summary>
    public async Task<IdentviaSession?> GetSessionAsync()
    {
        await _sessionLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_loaded) return _session;
            var json = await _store.GetAsync(Key("session")).ConfigureAwait(false);
            IdentviaSession? s = null;
            try { if (json is not null) s = JsonSerializer.Deserialize(json, IdentviaJson.Default.IdentviaSession); } catch (JsonException) { }
            if (s is not null) s = s with { Tokens = s.Tokens with { RefreshToken = await _store.GetAsync(Key("rt")).ConfigureAwait(false) } };
            _session = s; _loaded = true;
            return s;
        }
        finally { _sessionLock.Release(); }
    }

    private async Task SaveAsync(IdentviaSession? s)
    {
        await _sessionLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (s is not null)
            {
                if (s.Tokens.RefreshToken is { } rt) await _store.SetAsync(Key("rt"), rt).ConfigureAwait(false);
                else await _store.DeleteAsync(Key("rt")).ConfigureAwait(false);
                // The refresh token lives in its own entry.
                await _store.SetAsync(Key("session"), JsonSerializer.Serialize(s with { Tokens = s.Tokens with { RefreshToken = null } }, IdentviaJson.Default.IdentviaSession)).ConfigureAwait(false);
            }
            else
            {
                await _store.DeleteAsync(Key("session")).ConfigureAwait(false);
                await _store.DeleteAsync(Key("rt")).ConfigureAwait(false);
            }
            _session = s; _loaded = true;
        }
        finally { _sessionLock.Release(); }
        SessionChanged?.Invoke(this, s);
    }

    /// <summary>
    /// A valid access token, refreshed (and the refresh token rotated) shortly before expiry. Concurrent callers share one refresh.
    /// Throws <see cref="IdentviaLoginRequiredException"/> when the session has ended.
    /// </summary>
    public async Task<string> GetAccessTokenAsync(bool forceRefresh = false, CancellationToken ct = default)
    {
        var s = await GetSessionAsync().ConfigureAwait(false) ?? throw new IdentviaLoginRequiredException();
        if (!forceRefresh && s.Tokens.ExpiresAt - _core.Time.GetUtcNow() > _o.RefreshLeeway) return s.Tokens.AccessToken;
        Task<IdentviaSession> t;
        await _refreshLock.WaitAsync(ct).ConfigureAwait(false);
        try { t = _refreshing ??= RefreshAsync(s); }
        finally { _refreshLock.Release(); }
        try { return (await t.ConfigureAwait(false)).Tokens.AccessToken; }
        finally
        {
            await _refreshLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            if (_refreshing == t) _refreshing = null;
            _refreshLock.Release();
        }
    }

    private async Task<IdentviaSession> RefreshAsync(IdentviaSession s)
    {
        await Task.Yield();
        var rt = s.Tokens.RefreshToken;
        if (rt is null) { await SaveAsync(null).ConfigureAwait(false); throw new IdentviaLoginRequiredException(); }
        TokenSet t;
        try { t = await _core.TokenRequestAsync([new("grant_type", "refresh_token"), new("refresh_token", rt)], CancellationToken.None).ConfigureAwait(false); }
        catch (IdentviaTokenException e) when (e.Error == "invalid_grant")
        {
            // Expired, revoked, or reused; Identvia then revokes the whole token family.
            await SaveAsync(null).ConfigureAwait(false);
            throw new IdentviaLoginRequiredException();
        }
        var user = s.User;
        if (t.IdToken is not null)
        {
            var c = await _core.ValidateIdTokenAsync(t.IdToken, null, null, t.AccessToken, CancellationToken.None).ConfigureAwait(false);
            if (c.Str("sub") != s.User.Sub) throw new IdentviaValidationException("Refreshed ID token is for a different user.");
            user = IdentviaUser.From(c);
        }
        var n = new IdentviaSession(user, t with
        {
            RefreshToken = t.RefreshToken ?? rt, IdToken = t.IdToken ?? s.Tokens.IdToken, Scope = t.Scope ?? s.Tokens.Scope,
            AuthorizationDetails = t.AuthorizationDetails ?? s.Tokens.AuthorizationDetails,
        });
        await SaveAsync(n).ConfigureAwait(false);
        return n;
    }

    /// <summary>Calls userinfo with the current access token and checks <c>sub</c>.</summary>
    public async Task<System.Text.Json.Nodes.JsonObject> GetUserInfoAsync(CancellationToken ct = default)
    {
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        var at = await GetAccessTokenAsync(ct: ct).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Get, OidcCore.Endpoint(m.UserinfoEndpoint));
        req.Headers.Authorization = new("Bearer", at);
        using var res = await _core.Http.SendAsync(req, ct).ConfigureAwait(false);
        var o = JsonExt.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) ?? throw new IdentviaNetworkException($"userinfo returned invalid JSON ({(int)res.StatusCode}).");
        if (!res.IsSuccessStatusCode) throw new IdentviaTokenException(o.Str("error") ?? $"http_{(int)res.StatusCode}", o.Str("error_description"), (int)res.StatusCode);
        var s = await GetSessionAsync().ConfigureAwait(false);
        if (o.Str("sub") is not { } sub || (s is not null && !Util.SafeEquals(sub, s.User.Sub))) throw new IdentviaValidationException("userinfo is for a different user.");
        return o;
    }

    /// <summary>Deletes the local session and revokes the refresh token. <paramref name="federated"/> also ends the Identvia browser session.</summary>
    public async Task SignOutAsync(bool federated = false, string? postLogoutRedirectUri = null, CancellationToken ct = default)
    {
        var s = await GetSessionAsync().ConfigureAwait(false);
        await SaveAsync(null).ConfigureAwait(false);
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        if (s is not null && m.RevocationEndpoint is not null)
        {
            try
            {
                await _core.PostFormAsync(OidcCore.Endpoint(m.RevocationEndpoint),
                    [new("token", s.Tokens.RefreshToken ?? s.Tokens.AccessToken), new("token_type_hint", s.Tokens.RefreshToken is null ? "access_token" : "refresh_token")], ct).ConfigureAwait(false);
            }
            catch (IdentviaException) { /* local sign-out already happened */ }
        }
        if (federated && m.EndSessionEndpoint is not null)
        {
            var back = Identvia.RedirectUri.Validate(postLogoutRedirectUri ?? RedirectUri.AbsoluteUri);
            var q = new List<KeyValuePair<string, string>> { new("client_id", ClientId), new("post_logout_redirect_uri", back.AbsoluteUri), new("state", Util.RandomToken(16)) };
            if (s?.Tokens.IdToken is { } id) q.Add(new("id_token_hint", id));
            var b = OidcCore.Endpoint(m.EndSessionEndpoint).AbsoluteUri;
            try { await _browser.AuthenticateAsync(new Uri(b + (b.Contains('?') ? "&" : "?") + Util.Query(q)), back, ct).ConfigureAwait(false); }
            catch (IdentviaException) { }
        }
    }

    public void Dispose() { if (_ownsHttp) _core.Http.Dispose(); }
}

public sealed class SignInOptions
{
    public IList<string>? Scopes { get; set; }
    /// <summary>login, consent, select_account or none.</summary>
    public string? Prompt { get; set; }
    public int? MaxAge { get; set; }
    public string? LoginHint { get; set; }
    public IList<string>? UiLocales { get; set; }
    /// <summary>RFC 9396. Requires server 2026-10-21_5+.</summary>
    public IList<AuthorizationDetail>? AuthorizationDetails { get; set; }
}
