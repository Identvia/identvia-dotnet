using System.Text.Json.Nodes;

namespace Identvia;

public sealed class IdentviaServerClientOptions
{
    public string Issuer { get; set; } = IdentviaDefaults.Issuer;
    public required string ClientId { get; set; }
    /// <summary>Confidential clients only. Keep it on your server (configuration, a secret manager). Never ship it in an app.</summary>
    public required string ClientSecret { get; set; }
    public HttpClient? HttpClient { get; set; }
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}

public sealed record IntrospectionResult(bool Active, JsonObject Claims)
{
    public string? Sub => Claims.Str("sub");
    public string? Scope => Claims.Str("scope");
    public string? ClientId => Claims.Str("client_id");
}

public sealed record CibaRequest(string AuthReqId, int ExpiresIn, int Interval);

/// <summary>
/// Server-side calls for a <b>confidential</b> client (client_secret_basic): refresh, introspection and revocation, plus the
/// stage-5 delegation standards, RFC 8693 token exchange and OpenID CIBA. The stage-5 calls require server 2026-10-21_5+
/// and throw <see cref="IdentviaUnsupportedException"/> when discovery doesn't advertise them.
/// </summary>
public sealed class IdentviaServerClient : IDisposable
{
    public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string CibaGrant = "urn:openid:params:grant-type:ciba";
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    private readonly OidcCore _core;
    private readonly bool _ownsHttp;

    public IdentviaServerClient(IdentviaServerClientOptions o)
    {
        if (string.IsNullOrEmpty(o.ClientSecret)) throw new IdentviaConfigurationException("ClientSecret is required for IdentviaServerClient.");
        _ownsHttp = o.HttpClient is null;
        _core = new OidcCore(o.Issuer, o.ClientId, o.ClientSecret, o.HttpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) }, o.TimeProvider);
    }

    public Task<ProviderMetadata> GetDiscoveryAsync(CancellationToken ct = default) => _core.DiscoveryAsync(ct);

    /// <summary>Validates an ID token issued to this client (signature, iss, aud, exp, nonce if given).</summary>
    public Task<JsonObject> ValidateIdTokenAsync(string idToken, string? nonce = null, CancellationToken ct = default) =>
        _core.ValidateIdTokenAsync(idToken, nonce, null, null, ct);

    /// <summary>Uses a refresh token. Store the returned (rotated) refresh token: reusing the old one revokes the whole family.</summary>
    public async Task<TokenSet> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        try { return await _core.TokenRequestAsync([new("grant_type", "refresh_token"), new("refresh_token", refreshToken)], ct).ConfigureAwait(false); }
        catch (IdentviaTokenException e) when (e.Error == "invalid_grant") { throw new IdentviaLoginRequiredException(); }
    }

    /// <summary>RFC 7662: checks whether an access or refresh token is active.</summary>
    public async Task<IntrospectionResult> IntrospectAsync(string token, string? tokenTypeHint = null, CancellationToken ct = default)
    {
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        var f = new List<KeyValuePair<string, string>> { new("token", token) };
        if (tokenTypeHint is not null) f.Add(new("token_type_hint", tokenTypeHint));
        var (status, o) = await _core.PostFormAsync(OidcCore.Endpoint(m.IntrospectionEndpoint), f, ct).ConfigureAwait(false);
        if (status != 200 || o is null) throw new IdentviaTokenException(o?.Str("error") ?? $"http_{status}", o?.Str("error_description"), status);
        return new IntrospectionResult(o.Bool("active") == true, o);
    }

    public async Task RevokeAsync(string token, string? tokenTypeHint = null, CancellationToken ct = default)
    {
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        var f = new List<KeyValuePair<string, string>> { new("token", token) };
        if (tokenTypeHint is not null) f.Add(new("token_type_hint", tokenTypeHint));
        await _core.PostFormAsync(OidcCore.Endpoint(m.RevocationEndpoint), f, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// RFC 8693 token exchange (requires server 2026-10-21_5+). An agent (this client, the actor) trades the user's token for a
    /// narrower token carrying an <c>act</c> claim. Identvia allows delegation chains up to 3 deep.
    /// </summary>
    public async Task<TokenSet> ExchangeTokenAsync(string subjectToken, string? actorToken = null, string? audience = null, string? resource = null,
        IEnumerable<string>? scopes = null, IEnumerable<AuthorizationDetail>? authorizationDetails = null, CancellationToken ct = default)
    {
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        if (m.GrantTypesSupported?.Contains(TokenExchangeGrant) != true) throw new IdentviaUnsupportedException("Token exchange requires server 2026-10-21_5+ (grant not advertised in discovery).");
        var f = new List<KeyValuePair<string, string>> { new("grant_type", TokenExchangeGrant), new("subject_token", subjectToken), new("subject_token_type", AccessTokenType), new("requested_token_type", AccessTokenType) };
        if (actorToken is not null) { f.Add(new("actor_token", actorToken)); f.Add(new("actor_token_type", AccessTokenType)); }
        if (audience is not null) f.Add(new("audience", audience));
        if (resource is not null) f.Add(new("resource", resource));
        if (scopes is not null) f.Add(new("scope", string.Join(' ', scopes)));
        if (authorizationDetails?.ToList() is { Count: > 0 } ad) f.Add(new("authorization_details", AuthorizationDetail.Encode(ad)));
        return await _core.TokenRequestAsync(f, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// CIBA, OpenID Client-Initiated Backchannel Authentication (requires server 2026-10-21_5+). It asks the user (identified by
    /// <paramref name="loginHint"/>) to approve on their own device. Then poll with <see cref="PollCibaAsync"/> or <see cref="WaitForCibaAsync"/>.
    /// </summary>
    public async Task<CibaRequest> StartCibaAsync(string loginHint, string bindingMessage, IEnumerable<string>? scopes = null,
        IEnumerable<AuthorizationDetail>? authorizationDetails = null, int? requestedExpiry = null, CancellationToken ct = default)
    {
        var m = await _core.DiscoveryAsync(ct).ConfigureAwait(false);
        if (m.BackchannelAuthenticationEndpoint is null || m.GrantTypesSupported?.Contains(CibaGrant) != true)
            throw new IdentviaUnsupportedException("CIBA requires server 2026-10-21_5+ (not advertised in discovery).");
        var f = new List<KeyValuePair<string, string>> { new("scope", string.Join(' ', new[] { "openid" }.Concat(scopes ?? []).Distinct())), new("login_hint", loginHint), new("binding_message", bindingMessage) };
        if (requestedExpiry is int e) f.Add(new("requested_expiry", e.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        if (authorizationDetails?.ToList() is { Count: > 0 } ad) f.Add(new("authorization_details", AuthorizationDetail.Encode(ad)));
        var (status, o) = await _core.PostFormAsync(OidcCore.Endpoint(m.BackchannelAuthenticationEndpoint), f, ct).ConfigureAwait(false);
        if (status != 200 || o?.Str("auth_req_id") is not { } id) throw new IdentviaTokenException(o?.Str("error") ?? $"http_{status}", o?.Str("error_description"), status);
        return new CibaRequest(id, (int)(o.Num("expires_in") ?? 300), (int)(o.Num("interval") ?? 5));
    }

    /// <summary>One poll. Returns null while the user hasn't decided yet (<c>authorization_pending</c>/<c>slow_down</c>).</summary>
    public async Task<TokenSet?> PollCibaAsync(CibaRequest req, CancellationToken ct = default)
    {
        try { return await _core.TokenRequestAsync([new("grant_type", CibaGrant), new("auth_req_id", req.AuthReqId)], ct).ConfigureAwait(false); }
        catch (IdentviaTokenException e) when (e.Error is "authorization_pending" or "slow_down") { return null; }
    }

    /// <summary>Polls at the server's interval (+5 s after <c>slow_down</c>) until approved, denied (throws) or expired.</summary>
    public async Task<TokenSet> WaitForCibaAsync(CibaRequest req, CancellationToken ct = default)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(req.Interval, 1));
        var deadline = _core.Time.GetUtcNow().AddSeconds(req.ExpiresIn);
        while (_core.Time.GetUtcNow() < deadline)
        {
            await Task.Delay(interval, _core.Time, ct).ConfigureAwait(false);
            try
            {
                var t = await _core.TokenRequestAsync([new("grant_type", CibaGrant), new("auth_req_id", req.AuthReqId)], ct).ConfigureAwait(false);
                return t;
            }
            catch (IdentviaTokenException e) when (e.Error == "authorization_pending") { }
            catch (IdentviaTokenException e) when (e.Error == "slow_down") { interval += TimeSpan.FromSeconds(5); }
        }
        throw new IdentviaTokenException("expired_token", "The CIBA request expired.", 400);
    }

    public void Dispose() { if (_ownsHttp) _core.Http.Dispose(); }
}
