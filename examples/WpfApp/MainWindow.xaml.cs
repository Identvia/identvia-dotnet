using System.Windows;
using Identvia;

namespace WpfApp;

public partial class MainWindow : Window
{
    // Public client: the redirect is a fixed loopback port registered on the Identvia client. No secret in the app.
    private readonly IdentviaClient _identvia = new(
        new IdentviaClientOptions { ClientId = "oid_your_client_id", RedirectUri = "http://127.0.0.1:7890/callback" },
        new LoopbackBrowser(), new DpapiTokenStore("IdentviaWpfExample"));

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => Render(await _identvia.GetSessionAsync());
    }

    private async void OnSignIn(object sender, RoutedEventArgs e)
    {
        SignIn.IsEnabled = false;
        try { Render(await _identvia.SignInAsync()); Activate(); }
        catch (IdentviaCancelledException) { }
        catch (IdentviaException ex) { Status.Text = ex.Message; }
        finally { SignIn.IsEnabled = true; }
    }

    private async void OnSignOut(object sender, RoutedEventArgs e) { await _identvia.SignOutAsync(); Render(null); }

    private void Render(IdentviaSession? s)
    {
        SignIn.Visibility = s is null ? Visibility.Visible : Visibility.Collapsed;
        SignOut.Visibility = s is null ? Visibility.Collapsed : Visibility.Visible;
        Status.Text = s is null ? "" : $"Signed in as {s.User.Name ?? s.User.Email}\nPairwise sub: {s.User.Sub}";
    }
}
