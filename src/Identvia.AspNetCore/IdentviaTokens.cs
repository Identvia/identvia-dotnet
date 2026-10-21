using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Identvia.AspNetCore;

public static class IdentviaTokens
{
    private static readonly ConcurrentDictionary<string, Lazy<Task<JsonObject?>>> InFlight = new();

    /// <summary>
    /// The signed-in user's access token, refreshed when it expires within a minute. The rotated refresh token is written back
    /// to the session cookie, because Identvia revokes the whole token family when a refresh token is reused. Concurrent
    /// requests in this process share one refresh. Returns null when signed out. If the session has ended, it also clears the cookie.
    /// </summary>
    public static async Task<string?> GetIdentviaAccessTokenAsync(this HttpContext ctx,
        string cookieScheme = CookieAuthenticationDefaults.AuthenticationScheme, string scheme = IdentviaDefaults.AuthenticationScheme)
    {
        var auth = await ctx.AuthenticateAsync(cookieScheme).ConfigureAwait(false);
        if (!auth.Succeeded || auth.Properties is null) return null;
        var props = auth.Properties;
        var at = props.GetTokenValue("access_token");
        var time = ctx.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System;
        if (at is not null && DateTimeOffset.TryParse(props.GetTokenValue("expires_at"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var exp) &&
            exp - time.GetUtcNow() > TimeSpan.FromSeconds(60)) return at;
        var rt = props.GetTokenValue("refresh_token");
        if (rt is null) return at;

        var o = ctx.RequestServices.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme);
        var lazy = InFlight.GetOrAdd(rt, _ => new Lazy<Task<JsonObject?>>(() => RefreshAsync(o, rt, ctx.RequestAborted)));
        JsonObject? t;
        try { t = await lazy.Value.ConfigureAwait(false); }
        finally { _ = Task.Delay(TimeSpan.FromSeconds(10)).ContinueWith(_ => InFlight.TryRemove(rt, out var _), TaskScheduler.Default); }
        if (t is null)
        {
            await ctx.SignOutAsync(cookieScheme).ConfigureAwait(false);
            return null;
        }
        var newAt = t["access_token"]!.GetValue<string>();
        var tokens = new List<AuthenticationToken>
        {
            new() { Name = "access_token", Value = newAt },
            new() { Name = "refresh_token", Value = t["refresh_token"]?.GetValue<string>() ?? rt },
            new() { Name = "token_type", Value = "Bearer" },
            new() { Name = "expires_at", Value = time.GetUtcNow().AddSeconds(t["expires_in"]?.GetValue<double>() ?? 600).ToString("o", CultureInfo.InvariantCulture) },
        };
        if ((t["id_token"]?.GetValue<string>() ?? props.GetTokenValue("id_token")) is { } id) tokens.Add(new() { Name = "id_token", Value = id });
        props.StoreTokens(tokens);
        if (!ctx.Response.HasStarted) await ctx.SignInAsync(cookieScheme, auth.Principal!, props).ConfigureAwait(false);
        return newAt;
    }

    private static async Task<JsonObject?> RefreshAsync(OpenIdConnectOptions o, string rt, CancellationToken ct)
    {
        var cfg = await o.ConfigurationManager!.GetConfigurationAsync(ct).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token", ["refresh_token"] = rt, ["client_id"] = o.ClientId!, ["client_secret"] = o.ClientSecret!,
            }),
        };
        using var res = await o.Backchannel.SendAsync(req, ct).ConfigureAwait(false);
        var body = JsonNode.Parse(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) as JsonObject;
        if (res.IsSuccessStatusCode && body?["access_token"] is not null) return body;
        if (body?["error"]?.GetValue<string>() == "invalid_grant") return null;
        throw new IdentviaTokenException(body?["error"]?.GetValue<string>() ?? $"http_{(int)res.StatusCode}", body?["error_description"]?.GetValue<string>(), (int)res.StatusCode);
    }
}
