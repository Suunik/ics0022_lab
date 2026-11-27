using System.Windows;
using System.Windows.Threading;
using PasswordVault.App.Services;
using PasswordVault.App.ViewModels;
using PasswordVault.App.Views;
using PasswordVault.Core.Session;
using PasswordVault.Core.Storage;

namespace PasswordVault.App;

/// <summary>
/// Composes dependencies and ensures secrets and clipboard state are wiped on exit or failure.
/// </summary>
public sealed partial class App : Application, IDisposable
{
    private const string DefaultVaultName = "default";

    private MainViewModel? _mainViewModel;

    public void Dispose()
    {
        CleanupSession();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        Exit += OnApplicationExit;
        SessionEnding += OnSessionEnding;

        FileVaultStorage storage = new();
        WindowsUserIdentityProvider identityProvider = new();
        FileAuditLog auditLog = new(storage.BaseDirectory, identityProvider);
        SystemClock clock = new();

        VaultSession session = new(DefaultVaultName, storage, auditLog, clock, identityProvider);
        SecureClipboardService clipboardService = new();

        try
        {
            _mainViewModel = new MainViewModel(session, clipboardService);
            MainWindow window = new(_mainViewModel);
            MainWindow = window;
            window.Show();
        }
        catch
        {
            clipboardService.Dispose();
            session.Dispose();
            throw;
        }
    }

    private void OnApplicationExit(object sender, ExitEventArgs e)
    {
        CleanupSession();
    }

    private void OnSessionEnding(object sender, SessionEndingCancelEventArgs e)
    {
        CleanupSession();
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        CleanupSession();
        MessageBox.Show(
            "An unexpected error occurred and the vault has been locked.",
            "Secure Password Vault",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
        Shutdown(1);
    }

    private void CleanupSession()
    {
        _mainViewModel?.Dispose();
        _mainViewModel = null;
    }
}
