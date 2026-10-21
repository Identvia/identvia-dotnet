// dotnet user-secrets set Identvia:ClientSecret ivs_…   (never commit the secret)
// Register https://localhost:5001/signin-identvia as a redirect URI on a confidential Identvia client.
using Identvia.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddIdentviaAuthentication(o =>
{
    o.ClientId = builder.Configuration["Identvia:ClientId"] ?? "oid_your_client_id";
    o.ClientSecret = builder.Configuration["Identvia:ClientSecret"];
});
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapIdentviaEndpoints(); // GET /auth/login, POST /auth/logout

app.MapGet("/", (HttpContext c) => Results.Content(c.User.Identity?.IsAuthenticated == true
    ? $"<p>Hello {System.Net.WebUtility.HtmlEncode(c.User.Identity.Name)} (sub {System.Net.WebUtility.HtmlEncode(c.User.FindFirst("sub")?.Value)})</p><form method=post action=/auth/logout><button>Sign out</button></form>"
    : "<a href=\"/auth/login?returnUrl=/\">Sign in with Identvia</a>", "text/html"));

// Call your API with a fresh access token (rotated refresh token is written back to the cookie).
app.MapGet("/api-call", async (HttpContext c) => (await c.GetIdentviaAccessTokenAsync()) is { } at ? Results.Ok(new { tokenLength = at.Length }) : Results.Unauthorized())
   .RequireAuthorization();

app.Run();
