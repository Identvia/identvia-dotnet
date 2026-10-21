// Desktop/CLI sign-in with the system browser and a loopback redirect.
// Register http://127.0.0.1:7890/callback on a *public* Identvia client (no secret).
using Identvia;

using var identvia = new IdentviaClient(
    new IdentviaClientOptions { ClientId = args.FirstOrDefault() ?? "oid_your_client_id", RedirectUri = "http://127.0.0.1:7890/callback" },
    new LoopbackBrowser(),
    OperatingSystem.IsWindows() ? new DpapiTokenStore("IdentviaConsoleExample") : new InMemoryTokenStore());

var session = await identvia.GetSessionAsync() ?? await identvia.SignInAsync();
Console.WriteLine($"Signed in as {session.User.Name ?? session.User.Email} (sub {session.User.Sub})");
Console.WriteLine($"userinfo: {await identvia.GetUserInfoAsync()}");
