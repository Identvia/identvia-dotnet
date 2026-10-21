# Identvia for .NET

Sign in with [Identvia](https://identvia.com) from ASP.NET Core, WPF, WinUI, WinForms, MAUI and console apps.

| Package | For |
|---|---|
| `Identvia` | Native apps (public client: system browser + loopback/PKCE), plus `IdentviaServerClient` for back-end calls (introspection, token exchange, CIBA). |
| `Identvia.AspNetCore` | Web apps: `AddIdentvia()` on the built-in OpenID Connect handler. |

Every `sub` is **pairwise**: stable for your app, different in other apps. Key your users on it, not on the email.

## ASP.NET Core

```sh
dotnet add package Identvia.AspNetCore
dotnet user-secrets set Identvia:ClientSecret ivs_…
```

```csharp
builder.Services.AddIdentviaAuthentication(o =>
{
    o.ClientId = builder.Configuration["Identvia:ClientId"];
    o.ClientSecret = builder.Configuration["Identvia:ClientSecret"]; // confidential client: secret stays on the server
});
builder.Services.AddAuthorization();

app.UseAuthentication();
app.UseAuthorization();
app.MapIdentviaEndpoints();          // GET /auth/login?returnUrl=/x, POST /auth/logout

app.MapGet("/me", (HttpContext c) => c.User.FindFirst("sub")?.Value).RequireAuthorization();

// Access token for your API (refreshed and rotated automatically):
var token = await HttpContext.GetIdentviaAccessTokenAsync();
```

Register `https://your-app/signin-identvia` as the redirect URI and `https://your-app/signout-callback-identvia` as the post-logout URI. If you already call `AddAuthentication`, use `.AddIdentvia(o => …)` instead.

What `AddIdentvia` sets up:
- Authorization code flow with PKCE.
- The RFC 9207 `iss` check (mix-up defence).
- RS256/ES256 only, with raw OIDC claim names.
- Scopes `openid email profile offline_access`, and `SaveTokens`.
- A `__Host-` cookie that is Secure, HttpOnly and SameSite=Lax.

## Desktop: WPF, WinUI, WinForms, console

```sh
dotnet add package Identvia
```

```csharp
var identvia = new IdentviaClient(
    new IdentviaClientOptions { ClientId = "oid_…", RedirectUri = "http://127.0.0.1:7890/callback" },
    new LoopbackBrowser(),                       // opens the default browser, catches the redirect on 127.0.0.1
    new DpapiTokenStore("MyApp"));               // Windows: DPAPI, current user

var session = await identvia.GetSessionAsync() ?? await identvia.SignInAsync();
var token = await identvia.GetAccessTokenAsync(); // refreshes and rotates
await identvia.SignOutAsync();
```

Create a **public** client (no secret) and register the loopback URI **with its port**: Identvia's developer portal matches redirect URIs exactly. Never put a client secret in a desktop or mobile app.

## MAUI (Android, iOS, macOS)

Use a reverse-domain redirect (`com.example.app:/oauth/identvia`), MAUI's `WebAuthenticator` (which uses the system browser: ASWebAuthenticationSession or Custom Tabs) and `SecureStorage`:

```csharp
sealed class MauiBrowser : IAuthBrowser
{
    public async Task<Uri> AuthenticateAsync(Uri url, Uri redirect, CancellationToken ct)
    {
        try
        {
            var r = await WebAuthenticator.Default.AuthenticateAsync(new WebAuthenticatorOptions { Url = url, CallbackUrl = redirect });
            return new Uri(redirect + "?" + string.Join("&", r.Properties.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}")));
        }
        catch (TaskCanceledException) { throw new IdentviaCancelledException(); }
    }
}
sealed class MauiStore : ITokenStore
{
    public Task<string?> GetAsync(string k) => SecureStorage.Default.GetAsync(k);
    public Task SetAsync(string k, string v) => SecureStorage.Default.SetAsync(k, v);
    public Task DeleteAsync(string k) { SecureStorage.Default.Remove(k); return Task.CompletedTask; }
}
var identvia = new IdentviaClient(new() { ClientId = "oid_…", RedirectUri = "com.example.app:/oauth/identvia" }, new MauiBrowser(), new MauiStore());
```

On MAUI for Windows, use `LoopbackBrowser` and `DpapiTokenStore`.

## Server-to-server and agents (stage 5: requires server 2026-10-21_5+)

```csharp
using var server = new IdentviaServerClient(new() { ClientId = "oid_…", ClientSecret = secret });

var info = await server.IntrospectAsync(accessToken);

// RFC 8693: an agent swaps the user's token for a narrower, delegated one (act claim, chains up to 3 deep).
var delegated = await server.ExchangeTokenAsync(userAccessToken, audience: "https://api.example.com",
    authorizationDetails: [AuthorizationDetail.AgentTask("Order groceries", ["order"])]);

// CIBA: ask the user to approve on their phone
var req = await server.StartCibaAsync(loginHint: "ada@example.com", bindingMessage: "Approve order 42");
var tokens = await server.WaitForCibaAsync(req);
```

On older servers these throw `IdentviaUnsupportedException` (they read `grant_types_supported` and `backchannel_authentication_endpoint` from discovery).

## Tests

```sh
dotnet test --filter "Category!=Live"                                       # 64 unit + integration tests
IDENTVIA_LIVE_STATE=/tmp/live-state.json dotnet test --filter Category=Live # against a real server
```

The integration tests run the real ASP.NET Core OpenID Connect handler in TestServer against an in-memory Identvia.

MIT © Identvia
