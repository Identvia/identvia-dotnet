using System.Net;
using Identvia.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Identvia.Tests;

/// <summary>Drives the real ASP.NET Core OpenID Connect handler, configured by AddIdentvia, against the fake Identvia.</summary>
public sealed class WebApp : IAsyncDisposable
{
    public FakeIdentvia Idp { get; }
    public WebApplication App { get; }
    private readonly Dictionary<string, string> _cookies = [];
    public HttpClient Http { get; }

    private WebApp(FakeIdentvia idp, WebApplication app)
    {
        Idp = idp; App = app;
        Http = app.GetTestServer().CreateClient();
        Http.BaseAddress = new Uri("https://localhost");
    }

    public static async Task<WebApp> StartAsync(FakeIdentvia? idp = null)
    {
        idp ??= new FakeIdentvia();
        var b = WebApplication.CreateBuilder();
        b.WebHost.UseTestServer();
        b.Services.AddIdentviaAuthentication(o =>
        {
            o.Authority = T.Issuer;
            o.ClientId = T.ConfClientId;
            o.ClientSecret = T.ConfSecret;
            o.BackchannelHttpHandler = idp;
        });
        b.Services.AddAuthorization();
        var app = b.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapIdentviaEndpoints();
        app.MapGet("/me", (HttpContext c) => $"{c.User.FindFirst("sub")?.Value}|{c.User.Identity?.Name}").RequireAuthorization();
        app.MapGet("/token", async (HttpContext c) => await c.GetIdentviaAccessTokenAsync() ?? "none");
        await app.StartAsync();
        return new WebApp(idp, app);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod m, string url, Action<HttpRequestMessage>? edit = null)
    {
        var req = new HttpRequestMessage(m, url);
        if (_cookies.Count > 0) req.Headers.Add("Cookie", string.Join("; ", _cookies.Select(kv => $"{kv.Key}={kv.Value}")));
        edit?.Invoke(req);
        var res = await Http.SendAsync(req);
        if (res.Headers.TryGetValues("Set-Cookie", out var sc))
            foreach (var c in sc)
            {
                var nv = c.Split(';')[0].Split('=', 2);
                if (c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase)) _cookies.Remove(nv[0]); else _cookies[nv[0]] = nv[1];
            }
        return res;
    }

    public Task<HttpResponseMessage> GetAsync(string url) => SendAsync(HttpMethod.Get, url);

    /// <summary>Login → Identvia → callback. Returns the callback response.</summary>
    public async Task<HttpResponseMessage> SignInAsync(Func<string, string>? tamper = null)
    {
        var login = await GetAsync("/auth/login?returnUrl=/me");
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var cb = Idp.Authorize(login.Headers.Location!.AbsoluteUri);
        return await GetAsync(tamper?.Invoke(cb) ?? cb);
    }

    public async ValueTask DisposeAsync() { await App.StopAsync(); await App.DisposeAsync(); }
}

public class AspNetCoreTests
{
    [Fact]
    public async Task ChallengeUsesPkceStateNonceAndScopes()
    {
        await using var w = await WebApp.StartAsync();
        var res = await w.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        var loc = res.Headers.Location!;
        Assert.StartsWith($"{T.Issuer}/oauth/authorize", loc.AbsoluteUri);
        var q = T.Q(loc.AbsoluteUri);
        Assert.Equal("code", q["response_type"]); Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal("openid email profile offline_access", q["scope"]);
        Assert.Equal("https://localhost/signin-identvia", q["redirect_uri"]);
        Assert.True(q.ContainsKey("state") && q.ContainsKey("nonce") && q.ContainsKey("code_challenge"));
    }

    [Fact]
    public async Task FullSignInWithRealHandler()
    {
        await using var w = await WebApp.StartAsync();
        var cb = await w.SignInAsync();
        Assert.Equal(HttpStatusCode.Redirect, cb.StatusCode);
        Assert.Equal("/me", cb.Headers.Location!.OriginalString);
        var me = await w.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal($"{w.Idp.UserSub}|Ada", await me.Content.ReadAsStringAsync());
        // The code was redeemed with the confidential secret plus the PKCE verifier.
        var tokenReq = Util.ParseQuery(w.Idp.Requests.First(r => r.Path == "/oauth/token").Body);
        Assert.True(tokenReq.ContainsKey("code_verifier"));
    }

    [Fact]
    public async Task RejectsIssMixUp()
    {
        await using var w = await WebApp.StartAsync(new FakeIdentvia { WrongIss = true });
        var e = await Assert.ThrowsAnyAsync<Exception>(() => w.SignInAsync());
        Assert.Contains("does not match", e.ToString());
        Assert.DoesNotContain(w.Idp.Requests, r => r.Path == "/oauth/token");
    }

    [Fact]
    public async Task RejectsMissingIss()
    {
        await using var w = await WebApp.StartAsync(new FakeIdentvia { OmitIss = true });
        var e = await Assert.ThrowsAnyAsync<Exception>(() => w.SignInAsync());
        Assert.Contains("missing iss", e.ToString());
        Assert.DoesNotContain(w.Idp.Requests, r => r.Path == "/oauth/token");
    }

    [Fact]
    public async Task RejectsForgedState()
    {
        await using var w = await WebApp.StartAsync();
        var e = await Assert.ThrowsAnyAsync<Exception>(() => w.SignInAsync(u => System.Text.RegularExpressions.Regex.Replace(u, "state=[^&]+", "state=forged")));
        Assert.Contains("state", e.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(w.Idp.Requests, r => r.Path == "/oauth/token");
    }

    [Fact]
    public async Task RejectsNonceReplay()
    {
        await using var w = await WebApp.StartAsync(new FakeIdentvia { ForceNonce = "attacker" });
        var e = await Assert.ThrowsAnyAsync<Exception>(() => w.SignInAsync());
        Assert.Contains("nonce", e.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RefreshRotatesAndUpdatesTheCookie()
    {
        await using var w = await WebApp.StartAsync(new FakeIdentvia { ExpiresIn = 30 }); // inside the 60 s leeway → refresh
        await w.SignInAsync();
        var t1 = await (await w.GetAsync("/token")).Content.ReadAsStringAsync();
        Assert.StartsWith("at_", t1);
        Assert.Single(w.Idp.Requests, r => r.Path == "/oauth/token" && r.Body.Contains("grant_type=refresh_token"));
        // The rotated refresh token was saved in the cookie, so the next refresh works (no reuse → family not revoked).
        await Task.Delay(50);
        var t2 = await (await w.GetAsync("/token")).Content.ReadAsStringAsync();
        Assert.StartsWith("at_", t2);
        Assert.Empty(w.Idp.RevokedFamilies);
    }

    [Fact]
    public async Task LogoutIsSameOriginOnly()
    {
        await using var w = await WebApp.StartAsync();
        await w.SignInAsync();
        var cross = await w.SendAsync(HttpMethod.Post, "/auth/logout", r => r.Headers.Add("Origin", "https://evil.example"));
        Assert.Equal(HttpStatusCode.Forbidden, cross.StatusCode);
        var ok = await w.SendAsync(HttpMethod.Post, "/auth/logout", r => r.Headers.Add("Origin", "https://localhost"));
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.StartsWith($"{T.Issuer}/oauth/logout", ok.Headers.Location!.AbsoluteUri);
        Assert.Contains("id_token_hint=", ok.Headers.Location!.Query);
        Assert.Equal(HttpStatusCode.Redirect, (await w.GetAsync("/me")).StatusCode);
    }

    [Theory]
    [InlineData("/dash", "/dash")] [InlineData("//evil.com", "/")] [InlineData("/\\evil.com", "/")] [InlineData("https://evil.com", "/")] [InlineData(null, "/")]
    public void SafeReturnUrl(string? input, string expected) => Assert.Equal(expected, IdentviaEndpoints.SafeReturnUrl(input));

    [Fact]
    public void RequiresSecret()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentviaAuthentication(o => { o.ClientId = "x"; });
        using var sp = services.BuildServiceProvider();
        var e = Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>().Get(IdentviaDefaults.AuthenticationScheme));
        Assert.Contains("ClientSecret", e.Message);
    }
}
