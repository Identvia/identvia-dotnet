using System.Diagnostics;
using System.Net;
using System.Text.Json.Nodes;
using Identvia.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Identvia.Tests;

/// <summary>
/// Against a REAL Identvia server (stage 4+), with the state file from tools/live/helper.php:
///   IDENTVIA_LIVE_STATE=/tmp/live-state.json dotnet test --filter Category=Live
/// CI runs with --filter "Category!=Live".
/// </summary>
[Trait("Category", "Live")]
public class LiveTests
{
    private static readonly string? Path = Environment.GetEnvironmentVariable("IDENTVIA_LIVE_STATE") is { Length: > 0 } p ? p : null;
    private static JsonObject S => (JsonObject)JsonNode.Parse(File.ReadAllText(Path!))!;
    private static string Helper => System.IO.Path.GetFullPath(System.IO.Path.Combine(AppContext.BaseDirectory, "../../../../../../tools/live/helper.php"));

    private static string Browse(string url)
    {
        var psi = new ProcessStartInfo("php") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { Helper, "browse", Path!, url }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd().Trim();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new Exception("helper failed: " + p.StandardError.ReadToEnd());
        return o;
    }

    private sealed class HelperBrowser : IAuthBrowser
    {
        public Task<Uri> AuthenticateAsync(Uri url, Uri redirectUri, CancellationToken ct) =>
            Task.FromResult(url.AbsolutePath.EndsWith("/oauth/logout") ? redirectUri : new Uri(Browse(url.AbsoluteUri)));
    }

    [Fact]
    public async Task DesktopClientAgainstRealServer()
    {
        if (Path is null) return;
        var s = S;
        var store = new InMemoryTokenStore();
        using var c = new IdentviaClient(new IdentviaClientOptions
        {
            Issuer = s["base"]!.GetValue<string>(), ClientId = s["publicClientId"]!.GetValue<string>(), RedirectUri = s["publicRedirect"]!.GetValue<string>(),
            RefreshLeeway = TimeSpan.FromHours(1),
        }, new HelperBrowser(), store);
        var session = await c.SignInAsync();
        Assert.Equal(s["userEmail"]!.GetValue<string>(), session.User.Email);
        var rt1 = store.Values.First(kv => kv.Key.EndsWith(".rt")).Value;
        await c.GetAccessTokenAsync();
        Assert.NotEqual(rt1, store.Values.First(kv => kv.Key.EndsWith(".rt")).Value);
        Assert.Equal(session.User.Sub, (await c.GetUserInfoAsync())["sub"]!.GetValue<string>());

        // Confidential server helper: introspect the public client's token (Identvia: introspection is for confidential clients).
        using var server = new IdentviaServerClient(new IdentviaServerClientOptions { Issuer = s["base"]!.GetValue<string>(), ClientId = s["confClientId"]!.GetValue<string>(), ClientSecret = s["confSecret"]!.GetValue<string>() });
        var meta = await server.GetDiscoveryAsync();
        if (meta.IntrospectionEndpoint is not null) _ = await server.IntrospectAsync(await c.GetAccessTokenAsync());

        await c.SignOutAsync();
        Assert.Empty(store.Values);
    }

    [Fact]
    public async Task AspNetCoreHandlerAgainstRealServer()
    {
        if (Path is null) return;
        var s = S;
        var confRedirect = new Uri(s["confRedirect"]!.GetValue<string>()); // http://localhost:4301/auth/callback
        var b = WebApplication.CreateBuilder();
        b.WebHost.UseTestServer();
        b.Services.AddIdentviaAuthentication(o =>
        {
            o.Authority = s["base"]!.GetValue<string>();
            o.RequireHttpsMetadata = false; // local dev server only
            o.ClientId = s["confClientId"]!.GetValue<string>();
            o.ClientSecret = s["confSecret"]!.GetValue<string>();
            o.CallbackPath = confRedirect.AbsolutePath;
        });
        b.Services.AddAuthorization();
        await using var app = b.Build();
        app.UseAuthentication(); app.UseAuthorization(); app.MapIdentviaEndpoints();
        app.MapGet("/me", (HttpContext c) => c.User.FindFirst("email")?.Value).RequireAuthorization();
        await app.StartAsync();
        var http = app.GetTestServer().CreateClient();
        http.BaseAddress = new Uri($"{confRedirect.Scheme}://{confRedirect.Authority}");
        var jar = new Dictionary<string, string>();
        async Task<HttpResponseMessage> Get(string u)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, u);
            if (jar.Count > 0) req.Headers.Add("Cookie", string.Join("; ", jar.Select(kv => $"{kv.Key}={kv.Value}")));
            var res = await http.SendAsync(req);
            if (res.Headers.TryGetValues("Set-Cookie", out var sc)) foreach (var c in sc) { var nv = c.Split(';')[0].Split('=', 2); jar[nv[0]] = nv[1]; }
            return res;
        }
        var login = await Get("/auth/login?returnUrl=/me");
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var cb = await Get(Browse(login.Headers.Location!.AbsoluteUri));
        Assert.Equal(HttpStatusCode.Redirect, cb.StatusCode);
        var me = await Get("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(s["userEmail"]!.GetValue<string>(), await me.Content.ReadAsStringAsync());
    }
}
