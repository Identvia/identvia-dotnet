using System.Diagnostics;
using System.Net;
using System.Text;

namespace Identvia;

/// <summary>
/// Desktop sign-in (WPF, WinUI, WinForms, MAUI on Windows/macOS, console): opens the user's default browser and
/// catches the redirect on a loopback listener (RFC 8252 §7.3), e.g. <c>http://127.0.0.1:7890/callback</c>.
/// Register that exact URI on your Identvia client: the portal matches redirect URIs exactly, port included.
/// </summary>
public sealed class LoopbackBrowser : IAuthBrowser
{
    private readonly Func<Uri, Task> _open;
    private readonly TimeSpan _timeout;

    /// <param name="openBrowser">Opens a URL in the system browser. Defaults to the OS shell (<c>Process.Start</c> with UseShellExecute).</param>
    /// <param name="timeout">Gives up after this long (default 5 minutes).</param>
    public LoopbackBrowser(Func<Uri, Task>? openBrowser = null, TimeSpan? timeout = null)
    {
        _open = openBrowser ?? OpenSystemBrowser;
        _timeout = timeout ?? TimeSpan.FromMinutes(5);
    }

    /// <summary>HTML shown in the browser tab after the redirect.</summary>
    public string SuccessHtml { get; init; } =
        "<!doctype html><meta charset=utf-8><title>Signed in</title><body style=\"font-family:system-ui;text-align:center;padding-top:4rem\"><h1>You're signed in</h1><p>You can close this tab and return to the app.</p>";

    public async Task<Uri> AuthenticateAsync(Uri url, Uri redirectUri, CancellationToken ct)
    {
        if (redirectUri.Scheme != "http" || !RedirectUri.Loopback.Contains(redirectUri.Host))
            throw new IdentviaConfigurationException("LoopbackBrowser needs an http://127.0.0.1:port/path redirect URI.");
        if (redirectUri.IsDefaultPort) throw new IdentviaConfigurationException("Give the loopback redirect URI an explicit port, and register it on your Identvia client.");
        var host = redirectUri.Host == "::1" ? "[::1]" : redirectUri.Host;
        var path = redirectUri.AbsolutePath.EndsWith('/') ? redirectUri.AbsolutePath : redirectUri.AbsolutePath + "/";
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://{host}:{redirectUri.Port}{path}");
        try { listener.Start(); }
        catch (HttpListenerException e) { throw new IdentviaConfigurationException($"Could not listen on {redirectUri}: {e.Message} (is the port in use?)"); }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);
        await using var reg = cts.Token.Register(() => { try { listener.Stop(); } catch (ObjectDisposedException) { } });
        await _open(url).ConfigureAwait(false);
        while (true)
        {
            HttpListenerContext ctx;
            try { ctx = await listener.GetContextAsync().ConfigureAwait(false); }
            catch (Exception) when (cts.IsCancellationRequested) { throw new IdentviaCancelledException(ct.IsCancellationRequested ? "Sign-in was cancelled." : "Sign-in timed out."); }
            var reqUrl = ctx.Request.Url!;
            // Only the exact callback path with a state/code/error completes the sign-in; anything else (favicon, probes) gets a 404.
            if (ctx.Request.HttpMethod != "GET" || reqUrl.AbsolutePath != redirectUri.AbsolutePath || !(reqUrl.Query.Contains("state=") || reqUrl.Query.Contains("error=")))
            {
                ctx.Response.StatusCode = 404; ctx.Response.Close();
                continue;
            }
            var bytes = Encoding.UTF8.GetBytes(SuccessHtml);
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'";
            await ctx.Response.OutputStream.WriteAsync(bytes, ct).ConfigureAwait(false);
            ctx.Response.Close();
            // Rebuild from the registered redirect so the host is exactly what we registered.
            return new Uri(redirectUri.GetLeftPart(UriPartial.Path) + reqUrl.Query);
        }
    }

    private static Task OpenSystemBrowser(Uri url)
    {
        if (url.Scheme != "https" && !(url.Scheme == "http" && RedirectUri.Loopback.Contains(url.Host)))
            throw new IdentviaConfigurationException("Refusing to open a non-https URL.");
        Process.Start(new ProcessStartInfo(url.AbsoluteUri) { UseShellExecute = true });
        return Task.CompletedTask;
    }
}
