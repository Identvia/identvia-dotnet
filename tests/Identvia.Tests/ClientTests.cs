using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Identvia;
using Xunit;

namespace Identvia.Tests;

public sealed class Ctx : IDisposable
{
    public FakeIdentvia Idp { get; }
    public FakeBrowser Browser { get; }
    public InMemoryTokenStore Store { get; } = new();
    public IdentviaClient Client { get; }

    public Ctx(FakeIdentvia? idp = null, TimeSpan? leeway = null)
    {
        Idp = idp ?? new FakeIdentvia();
        Browser = new FakeBrowser(Idp);
        Client = new IdentviaClient(new IdentviaClientOptions { Issuer = T.Issuer, ClientId = T.ClientId, RedirectUri = T.Redirect, HttpClient = Idp.Client(), RefreshLeeway = leeway ?? TimeSpan.FromSeconds(60) }, Browser, Store);
    }

    public void Dispose() => Client.Dispose();
}

public class PkceTests
{
    [Fact] public void Rfc7636Vector() => Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.ChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

    [Fact]
    public void Generate()
    {
        var a = Pkce.Generate(); var b = Pkce.Generate();
        Assert.Equal(43, a.Verifier.Length); Assert.NotEqual(a.Verifier, b.Verifier);
        Assert.Equal(Pkce.ChallengeFor(a.Verifier), a.Challenge);
        Assert.Throws<IdentviaConfigurationException>(() => Pkce.ChallengeFor("short"));
        Assert.Throws<IdentviaConfigurationException>(() => Pkce.ChallengeFor(new string('a', 42) + "!"));
    }

    [Fact]
    public void Base64UrlRoundTrip()
    {
        Assert.Equal("-_8", Base64Url.Encode(new byte[] { 0xfb, 0xff }));
        Assert.Null(Base64Url.Decode("a+b="));
    }
}

public class ConfigTests
{
    [Theory]
    [InlineData("http://127.0.0.1:7890/callback")] [InlineData("http://localhost:7890/cb")] [InlineData("com.example.app:/cb")] [InlineData("https://app.example.com/cb")]
    public void GoodRedirects(string u) => RedirectUri.Validate(u);

    [Theory]
    [InlineData("myapp://cb")] [InlineData("http://app.example.com/cb")] [InlineData("com.example.app:/cb#x")] [InlineData("javascript:alert(1)")] [InlineData("not a uri")]
    public void BadRedirects(string u) => Assert.Throws<IdentviaConfigurationException>(() => RedirectUri.Validate(u));

    [Fact]
    public void Matches()
    {
        Assert.True(RedirectUri.Matches(new Uri("http://127.0.0.1:7890/callback?code=1"), new Uri(T.Redirect)));
        Assert.False(RedirectUri.Matches(new Uri("http://127.0.0.1:7891/callback?code=1"), new Uri(T.Redirect)));
        Assert.False(RedirectUri.Matches(new Uri("http://127.0.0.1:7890/other?code=1"), new Uri(T.Redirect)));
    }

    [Fact]
    public void IssuerAndClient()
    {
        var b = new FakeBrowser(new FakeIdentvia());
        Assert.Throws<IdentviaConfigurationException>(() => new IdentviaClient(new() { Issuer = "http://id.identvia.com", ClientId = "x", RedirectUri = T.Redirect }, b, new InMemoryTokenStore()));
        Assert.Throws<IdentviaConfigurationException>(() => new IdentviaClient(new() { ClientId = " ", RedirectUri = T.Redirect }, b, new InMemoryTokenStore()));
        Assert.Equal("https://id.identvia.com", new IdentviaClient(new() { Issuer = "https://id.identvia.com/", ClientId = "x", RedirectUri = T.Redirect }, b, new InMemoryTokenStore()).Issuer);
        Assert.Throws<IdentviaConfigurationException>(() => new IdentviaServerClient(new() { ClientId = "x", ClientSecret = "" }));
    }
}

public class SignInTests
{
    [Fact]
    public async Task FullFlow()
    {
        using var c = new Ctx();
        IdentviaSession? changed = null;
        c.Client.SessionChanged += (_, s) => changed = s;
        var s = await c.Client.SignInAsync(new SignInOptions { Prompt = "login" });
        Assert.Equal(c.Idp.UserSub, s.User.Sub); Assert.Equal("ada@example.com", s.User.Email);
        var q = T.Q(c.Browser.Opened.Single().AbsoluteUri);
        Assert.Equal("S256", q["code_challenge_method"]); Assert.Equal("openid email profile offline_access", q["scope"]); Assert.Equal("login", q["prompt"]);
        Assert.Equal(new[] { $"identvia.{T.ClientId}.rt", $"identvia.{T.ClientId}.session" }, c.Store.Values.Keys.Order());
        Assert.DoesNotContain("rt_", c.Store.Values[$"identvia.{T.ClientId}.session"]);
        Assert.DoesNotContain(c.Idp.Requests, r => r.Body.Contains("client_secret") || r.Auth is not null && r.Path == "/oauth/token");
        Assert.Equal(s, changed);
    }

    [Fact]
    public async Task Cancelled()
    {
        using var c = new Ctx(); c.Browser.Cancel = true;
        await Assert.ThrowsAsync<IdentviaCancelledException>(() => c.Client.SignInAsync());
        Assert.Empty(c.Store.Values);
    }

    [Fact]
    public async Task AccessDenied()
    {
        using var c = new Ctx(); c.Browser.Deny = true;
        var e = await Assert.ThrowsAsync<IdentviaAuthorizationException>(() => c.Client.SignInAsync());
        Assert.Equal("access_denied", e.Error); Assert.Equal("The user denied access", e.Description);
    }

    [Fact]
    public async Task ForgedState()
    {
        using var c = new Ctx();
        c.Browser.Tamper = u => System.Text.RegularExpressions.Regex.Replace(u, "state=[^&]+", "state=forged");
        await Assert.ThrowsAsync<IdentviaInvalidStateException>(() => c.Client.SignInAsync());
    }

    [Fact]
    public async Task OtherRedirect()
    {
        using var c = new Ctx();
        c.Browser.Tamper = u => u.Replace("127.0.0.1:7890", "127.0.0.1:7891");
        await Assert.ThrowsAsync<IdentviaInvalidStateException>(() => c.Client.SignInAsync());
    }

    [Fact]
    public async Task IssMixUp()
    {
        using (var c = new Ctx(new FakeIdentvia { WrongIss = true })) await Assert.ThrowsAsync<IdentviaInvalidStateException>(() => c.Client.SignInAsync());
        using (var c = new Ctx(new FakeIdentvia { OmitIss = true })) await Assert.ThrowsAsync<IdentviaInvalidStateException>(() => c.Client.SignInAsync());
    }

    [Fact]
    public async Task NonceReplay()
    {
        using var c = new Ctx(new FakeIdentvia { ForceNonce = "attacker" });
        var e = await Assert.ThrowsAsync<IdentviaValidationException>(() => c.Client.SignInAsync());
        Assert.Contains("nonce", e.Message);
    }

    [Fact]
    public async Task CodeReplayAndWrongVerifier()
    {
        using var c = new Ctx();
        var (url, tx) = await c.Client.CreateAuthorizationRequestAsync();
        var cb = new Uri(c.Idp.Authorize(url.AbsoluteUri));
        await c.Client.CompleteAuthorizationAsync(cb, tx);
        Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<IdentviaTokenException>(() => c.Client.CompleteAuthorizationAsync(cb, tx))).Error);
        var (url2, tx2) = await c.Client.CreateAuthorizationRequestAsync();
        var e = await Assert.ThrowsAsync<IdentviaTokenException>(() => c.Client.CompleteAuthorizationAsync(new Uri(c.Idp.Authorize(url2.AbsoluteUri)), tx2 with { CodeVerifier = Pkce.Generate().Verifier }));
        Assert.Contains("PKCE", e.Description);
    }
}

public class IdTokenTests
{
    private static readonly JsonObject K1 = new() { ["alg"] = "RS256", ["kid"] = "k1" };

    private static async Task Reject(string needle, Func<JsonObject, JsonObject>? patch = null, JsonObject? header = null, RSA? key = null)
    {
        var idp = new FakeIdentvia();
        idp.IdTokenOverride = c => T.SignRs256(header ?? K1, patch?.Invoke(c) ?? c, key ?? idp.Rsa);
        using var ctx = new Ctx(idp);
        var e = await Assert.ThrowsAsync<IdentviaValidationException>(() => ctx.Client.SignInAsync());
        Assert.Contains(needle, e.Message);
    }

    [Fact] public Task WrongIssuer() => Reject("issuer", c => c.With(("iss", "https://evil.example")));
    [Fact] public Task WrongAudience() => Reject("aud", c => c.With(("aud", "other"), ("azp", "other")));
    [Fact] public Task MultiAudNeedsAzp() => Reject("azp", c => c.With(("aud", new JsonArray(T.ClientId, "other")), ("azp", null)));
    [Fact] public Task Expired() => Reject("expired", c => c.With(("exp", 1000), ("iat", 900)));
    [Fact] public Task FutureIat() => Reject("future", c => c.With(("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600)));
    [Fact] public Task MissingSub() => Reject("sub", c => c.With(("sub", null)));
    [Fact] public Task AtHash() => Reject("at_hash", c => c.With(("at_hash", "AAAAAAAAAAAAAAAAAAAAAA")));
    [Fact] public Task OtherKey() => Reject("signature", key: RSA.Create(2048));
    [Fact] public Task UnknownKid() => Reject("unknown key", header: new JsonObject { ["alg"] = "RS256", ["kid"] = "nope" });

    [Fact]
    public async Task AlgNone()
    {
        var idp = new FakeIdentvia { IdTokenOverride = c => $"{T.B64(new JsonObject { ["alg"] = "none", ["kid"] = "k1" })}.{T.B64(c)}." };
        using var ctx = new Ctx(idp);
        Assert.Contains("none", (await Assert.ThrowsAsync<IdentviaValidationException>(() => ctx.Client.SignInAsync())).Message);
    }

    [Fact]
    public async Task Hs256Confusion()
    {
        var idp = new FakeIdentvia();
        idp.IdTokenOverride = c =>
        {
            var input = $"{T.B64(new JsonObject { ["alg"] = "HS256", ["kid"] = "k1" })}.{T.B64(c)}";
            return $"{input}.{Base64Url.Encode(HMACSHA256.HashData(idp.Rsa.ExportParameters(false).Modulus!, Encoding.ASCII.GetBytes(input)))}";
        };
        using var ctx = new Ctx(idp);
        Assert.Contains("HS256", (await Assert.ThrowsAsync<IdentviaValidationException>(() => ctx.Client.SignInAsync())).Message);
    }

    [Fact]
    public async Task Es256Accepted()
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var idp = new FakeIdentvia { Ec = ec };
        idp.IdTokenOverride = c => T.SignEs256(new JsonObject { ["alg"] = "ES256", ["kid"] = "ec1" }, c, ec);
        using var ctx = new Ctx(idp);
        Assert.Equal(idp.UserSub, (await ctx.Client.SignInAsync()).User.Sub);
    }

    [Fact]
    public async Task KeyRotationRefetchIsRateLimited()
    {
        var idp = new FakeIdentvia();
        using var c = new Ctx(idp);
        await c.Client.SignInAsync();
        Assert.Equal(1, idp.JwksFetches);
        idp.Rsa = RSA.Create(2048); idp.Kid = "k2";
        await Assert.ThrowsAsync<IdentviaValidationException>(() => c.Client.SignInAsync());
        Assert.Equal(1, idp.JwksFetches);
        using var fresh = new Ctx(idp);
        await fresh.Client.SignInAsync();
    }

    [Fact]
    public async Task MaxAge()
    {
        var idp = new FakeIdentvia();
        idp.IdTokenOverride = c => T.SignRs256(K1, c.With(("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 7200)), idp.Rsa);
        using var ctx = new Ctx(idp);
        Assert.Contains("max_age", (await Assert.ThrowsAsync<IdentviaValidationException>(() => ctx.Client.SignInAsync(new SignInOptions { MaxAge = 60 }))).Message);
    }
}

public class TokenTests
{
    [Fact]
    public async Task RotationSingleFlight()
    {
        using var c = new Ctx(leeway: TimeSpan.FromHours(1));
        await c.Client.SignInAsync();
        var rt1 = c.Store.Values[$"identvia.{T.ClientId}.rt"];
        c.Idp.TokenDelayMs = 50;
        var r = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => c.Client.GetAccessTokenAsync()));
        Assert.Single(r.Distinct());
        Assert.Single(c.Idp.Requests, x => x.Path == "/oauth/token" && x.Body.Contains("grant_type=refresh_token"));
        Assert.NotEqual(rt1, c.Store.Values[$"identvia.{T.ClientId}.rt"]);
    }

    [Fact]
    public async Task ReuseDetectionSignsOut()
    {
        using var c = new Ctx(leeway: TimeSpan.FromHours(1));
        await c.Client.SignInAsync();
        var old = c.Store.Values[$"identvia.{T.ClientId}.rt"];
        await c.Client.GetAccessTokenAsync();
        using var http = c.Idp.Client();
        await http.PostAsync($"{T.Issuer}/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = old, ["client_id"] = T.ClientId }));
        await Assert.ThrowsAsync<IdentviaLoginRequiredException>(() => c.Client.GetAccessTokenAsync());
        Assert.Empty(c.Store.Values);
        Assert.Null(await c.Client.GetSessionAsync());
    }

    [Fact]
    public async Task FreshTokenNoRefresh()
    {
        using var c = new Ctx();
        var s = await c.Client.SignInAsync();
        Assert.Equal(s.Tokens.AccessToken, await c.Client.GetAccessTokenAsync());
        Assert.Single(c.Idp.Requests, x => x.Path == "/oauth/token");
    }

    [Fact]
    public async Task RestoreAndUserinfo()
    {
        using var c = new Ctx();
        await c.Client.SignInAsync();
        using var again = new IdentviaClient(new IdentviaClientOptions { Issuer = T.Issuer, ClientId = T.ClientId, RedirectUri = T.Redirect, HttpClient = c.Idp.Client() }, c.Browser, c.Store);
        var s = await again.GetSessionAsync();
        Assert.Equal(c.Idp.UserSub, s?.User.Sub); Assert.NotNull(s?.Tokens.RefreshToken);
        Assert.Equal(c.Idp.UserSub, (await again.GetUserInfoAsync())["sub"]!.GetValue<string>());
    }

    [Fact]
    public async Task SignOut()
    {
        using var c = new Ctx();
        await c.Client.SignInAsync();
        await c.Client.SignOutAsync(federated: true);
        Assert.Single(c.Idp.RevokedFamilies); Assert.Empty(c.Store.Values);
        var q = T.Q(c.Browser.Opened.Last().AbsoluteUri);
        Assert.True(q.ContainsKey("id_token_hint")); Assert.Equal(T.Redirect, q["post_logout_redirect_uri"]);
    }

    [Fact]
    public async Task RarNeedsStage5()
    {
        using (var c = new Ctx())
            Assert.Contains("2026-10-21_5", (await Assert.ThrowsAsync<IdentviaUnsupportedException>(() => c.Client.SignInAsync(new SignInOptions { AuthorizationDetails = [AuthorizationDetail.AgentTask("x")] }))).Message);
        using var c5 = new Ctx(new FakeIdentvia { Stage5 = true });
        var s = await c5.Client.SignInAsync(new SignInOptions { AuthorizationDetails = [AuthorizationDetail.AgentTask("Order groceries", ["order"])] });
        var d = (JsonObject)s.Tokens.AuthorizationDetails![0]!;
        Assert.Equal("agent_task", d["type"]!.GetValue<string>());
        Assert.Equal("order", d["actions"]![0]!.GetValue<string>());
    }
}
