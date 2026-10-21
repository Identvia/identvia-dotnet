using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Identvia.AspNetCore;

public static class IdentviaEndpoints
{
    /// <summary>
    /// <c>GET {prefix}/login?returnUrl=/path</c> starts sign-in. <c>POST {prefix}/logout</c> signs out locally and at Identvia;
    /// it's same-origin only, so other sites can't log your users out.
    /// </summary>
    public static IEndpointConventionBuilder MapIdentviaEndpoints(this IEndpointRouteBuilder app, string prefix = "/auth", string scheme = IdentviaDefaults.AuthenticationScheme)
    {
        var g = app.MapGroup(prefix);
        g.MapGet("/login", (string? returnUrl) =>
            Results.Challenge(new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) }, [scheme]));
        g.MapPost("/logout", (HttpContext ctx) =>
        {
            if (!IsSameOrigin(ctx.Request)) return Results.StatusCode(StatusCodes.Status403Forbidden);
            return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" }, [CookieAuthenticationDefaults.AuthenticationScheme, scheme]);
        });
        return g;
    }

    /// <summary>Only local paths: <c>/x</c> yes; <c>//evil.com</c>, <c>/\evil.com</c>, <c>https://…</c> no.</summary>
    public static string SafeReturnUrl(string? u) =>
        !string.IsNullOrEmpty(u) && u[0] == '/' && (u.Length == 1 || (u[1] != '/' && u[1] != '\\')) && !u.Any(char.IsControl) ? u : "/";

    internal static bool IsSameOrigin(HttpRequest r)
    {
        var site = r.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0) return site is "same-origin" or "none";
        var origin = r.Headers.Origin.ToString();
        if (origin.Length == 0) return false;
        return string.Equals(origin, $"{r.Scheme}://{r.Host}", StringComparison.OrdinalIgnoreCase);
    }
}
