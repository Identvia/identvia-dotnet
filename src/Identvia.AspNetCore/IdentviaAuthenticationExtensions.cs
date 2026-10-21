using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Identvia.AspNetCore;

public static class IdentviaAuthenticationExtensions
{
    /// <summary>
    /// Adds "Sign in with Identvia": the ASP.NET Core OpenID Connect handler with Identvia's defaults. Those are the code flow with PKCE,
    /// an RFC 9207 <c>iss</c> check, RS256/ES256 only, raw OIDC claim names (<c>sub</c>, <c>email</c>, <c>name</c>), saved tokens
    /// and the <c>offline_access</c> scope for refresh. Set <c>ClientId</c> and <c>ClientSecret</c> in <paramref name="configure"/>.
    /// </summary>
    public static AuthenticationBuilder AddIdentvia(this AuthenticationBuilder builder, Action<OpenIdConnectOptions> configure) =>
        builder.AddIdentvia(IdentviaDefaults.AuthenticationScheme, IdentviaDefaults.DisplayName, configure);

    public static AuthenticationBuilder AddIdentvia(this AuthenticationBuilder builder, string scheme, string displayName, Action<OpenIdConnectOptions> configure)
    {
        builder.AddOpenIdConnect(scheme, displayName, o =>
        {
            ApplyDefaults(o);
            configure(o);
        });
        builder.Services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>>(new IdentviaPostConfigure(scheme));
        return builder;
    }

    /// <summary>
    /// The usual setup in one call: cookie sessions, Identvia as the challenge scheme. Then call
    /// <c>app.UseAuthentication(); app.UseAuthorization(); app.MapIdentviaEndpoints();</c>.
    /// </summary>
    public static AuthenticationBuilder AddIdentviaAuthentication(this IServiceCollection services, Action<OpenIdConnectOptions> configure,
        Action<CookieAuthenticationOptions>? cookie = null) =>
        services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = IdentviaDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.Cookie.Name = "__Host-identvia";
                o.Cookie.HttpOnly = true;
                o.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
                o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                o.SlidingExpiration = true;
                o.ExpireTimeSpan = TimeSpan.FromDays(14);
                cookie?.Invoke(o);
            })
            .AddIdentvia(configure);

    internal static void ApplyDefaults(OpenIdConnectOptions o)
    {
        o.Authority = IdentviaDefaults.Issuer;
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.ResponseMode = OpenIdConnectResponseMode.Query;
        o.UsePkce = true;
        o.Scope.Clear();
        foreach (var s in new[] { "openid", "email", "profile", "offline_access" }) o.Scope.Add(s);
        o.SaveTokens = true;
        o.GetClaimsFromUserInfoEndpoint = false; // the ID token already carries them
        o.MapInboundClaims = false;
        o.CallbackPath = "/signin-identvia";
        o.SignedOutCallbackPath = "/signout-callback-identvia";
        o.RequireHttpsMetadata = true;
        o.TokenValidationParameters.NameClaimType = "name";
        o.TokenValidationParameters.RoleClaimType = "roles";
        o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.EcdsaSha256];
        o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(60);
    }

    private sealed class IdentviaPostConfigure(string scheme) : IPostConfigureOptions<OpenIdConnectOptions>
    {
        public void PostConfigure(string? name, OpenIdConnectOptions o)
        {
            if (name != scheme) return;
            if (string.IsNullOrEmpty(o.ClientId)) throw new InvalidOperationException("AddIdentvia: ClientId is required.");
            if (string.IsNullOrEmpty(o.ClientSecret)) throw new InvalidOperationException("AddIdentvia: ClientSecret is required (server apps are confidential clients). Keep it in configuration or a secret store.");
            // Non-negotiable: code flow + PKCE.
            o.ResponseType = OpenIdConnectResponseType.Code;
            o.UsePkce = true;
            var prev = o.Events.OnMessageReceived;
            o.Events.OnMessageReceived = async ctx =>
            {
                // RFC 9207: the authorization response must come from the issuer we started with (mix-up defence).
                var cfg = await ctx.Options.ConfigurationManager!.GetConfigurationAsync(ctx.HttpContext.RequestAborted).ConfigureAwait(false);
                var iss = ctx.ProtocolMessage.Iss;
                var supported = cfg.AdditionalData.TryGetValue("authorization_response_iss_parameter_supported", out var v) && v switch
                {
                    bool b => b,
                    JsonElement je => je.ValueKind == JsonValueKind.True,
                    string s => s == "true",
                    _ => false,
                };
                if (iss is not null && iss != cfg.Issuer) { ctx.Fail($"Authorization response iss '{iss}' does not match '{cfg.Issuer}'."); return; }
                if (iss is null && supported) { ctx.Fail("Authorization response is missing iss (RFC 9207)."); return; }
                await prev(ctx).ConfigureAwait(false);
            };
        }
    }
}
