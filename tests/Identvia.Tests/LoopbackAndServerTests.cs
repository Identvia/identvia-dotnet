using System.Net;
using System.Net.Sockets;
using Identvia;
using Xunit;

namespace Identvia.Tests;

public class LoopbackBrowserTests
{
    private static int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); var p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }

    [Fact]
    public async Task FullDesktopFlowThroughARealLoopbackListener()
    {
        var port = FreePort();
        var redirect = $"http://127.0.0.1:{port}/callback";
        var idp = new FakeIdentvia(); idp.RedirectUris.Add(redirect);
        using var http = new HttpClient();
        string? page = null;
        Task? visit = null;
        // The "system browser": hits a decoy path first, then follows Identvia's redirect to the loopback listener.
        var browser = new LoopbackBrowser(async url =>
        {
            visit = Task.Run(async () =>
            {
                await Task.Delay(100);
                Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"http://127.0.0.1:{port}/callback/favicon.ico")).StatusCode);
                page = await http.GetStringAsync(idp.Authorize(url.AbsoluteUri));
            });
            await Task.CompletedTask;
        });
        using var c = new IdentviaClient(new IdentviaClientOptions { Issuer = T.Issuer, ClientId = T.ClientId, RedirectUri = redirect, HttpClient = idp.Client() }, browser, new InMemoryTokenStore());
        var s = await c.SignInAsync();
        Assert.Equal(idp.UserSub, s.User.Sub);
        await visit!.WaitAsync(TimeSpan.FromSeconds(10)); // surfaces the browser side's exceptions
        Assert.Contains("You're signed in", page);
    }

    [Fact]
    public async Task TimesOutAsCancelled()
    {
        var port = FreePort();
        var b = new LoopbackBrowser(_ => Task.CompletedTask, TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAsync<IdentviaCancelledException>(() => b.AuthenticateAsync(new Uri("https://id.identvia.test/oauth/authorize"), new Uri($"http://127.0.0.1:{port}/cb"), default));
    }

    [Fact]
    public async Task RejectsNonLoopbackRedirects()
    {
        var b = new LoopbackBrowser(_ => Task.CompletedTask);
        await Assert.ThrowsAsync<IdentviaConfigurationException>(() => b.AuthenticateAsync(new Uri("https://x"), new Uri("com.example.app:/cb"), default));
        await Assert.ThrowsAsync<IdentviaConfigurationException>(() => b.AuthenticateAsync(new Uri("https://x"), new Uri("http://127.0.0.1/cb"), default));
    }
}

public class ServerClientTests
{
    private static IdentviaServerClient Make(FakeIdentvia idp) => new(new IdentviaServerClientOptions { Issuer = T.Issuer, ClientId = T.ConfClientId, ClientSecret = T.ConfSecret, HttpClient = idp.Client() });

    private static async Task<string> UserToken(FakeIdentvia idp)
    {
        using var c = new Ctx(idp);
        return (await c.Client.SignInAsync()).Tokens.AccessToken;
    }

    [Fact]
    public async Task IntrospectUsesBasicAuth()
    {
        var idp = new FakeIdentvia();
        var at = await UserToken(idp);
        using var s = Make(idp);
        var r = await s.IntrospectAsync(at);
        Assert.True(r.Active); Assert.Equal(idp.UserSub, r.Sub);
        Assert.False((await s.IntrospectAsync("nope")).Active);
        Assert.Equal("Basic", idp.Requests.Last().Auth);
        Assert.DoesNotContain(T.ConfSecret, idp.Requests.Last().Body);
    }

    [Fact]
    public async Task Stage5HelpersThrowUnsupportedOnStage4()
    {
        using var s = Make(new FakeIdentvia());
        Assert.Contains("2026-10-21_5", (await Assert.ThrowsAsync<IdentviaUnsupportedException>(() => s.ExchangeTokenAsync("at"))).Message);
        Assert.Contains("2026-10-21_5", (await Assert.ThrowsAsync<IdentviaUnsupportedException>(() => s.StartCibaAsync("ada@example.com", "Approve order 42"))).Message);
    }

    [Fact]
    public async Task TokenExchange()
    {
        var idp = new FakeIdentvia { Stage5 = true };
        var at = await UserToken(idp);
        using var s = Make(idp);
        var t = await s.ExchangeTokenAsync(at, audience: "https://api.example.com", scopes: ["orders:write"], authorizationDetails: [AuthorizationDetail.AgentTask("Order groceries")]);
        Assert.StartsWith("at_x_", t.AccessToken);
        Assert.Equal(IdentviaServerClient.AccessTokenType, t.IssuedTokenType);
        var body = Util.ParseQuery(idp.Requests.Last(r => r.Path == "/oauth/token").Body);
        Assert.Equal(IdentviaServerClient.TokenExchangeGrant, body["grant_type"]);
        Assert.Contains("agent_task", body["authorization_details"]);
    }

    [Fact]
    public async Task CibaPollsUntilApproved()
    {
        var idp = new FakeIdentvia { Stage5 = true };
        using var s = Make(idp);
        var req = await s.StartCibaAsync("ada@example.com", "Approve order 42");
        Assert.Null(await s.PollCibaAsync(req));
        var t = await s.WaitForCibaAsync(req);
        Assert.NotNull(t.AccessToken);
        Assert.Equal(2, idp.CibaPolls);
    }

    [Fact]
    public async Task RefreshRotationAndReuse()
    {
        var idp = new FakeIdentvia();
        using var c = new Ctx(idp);
        await c.Client.SignInAsync();
        using var s = Make(idp);
        await Assert.ThrowsAsync<IdentviaLoginRequiredException>(() => s.RefreshAsync(c.Store.Values[$"identvia.{T.ClientId}.rt"])); // another client's token
    }
}
