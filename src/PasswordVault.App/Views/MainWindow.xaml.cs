using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using PasswordVault.App.Services;
using PasswordVault.App.ViewModels;
using PasswordVault.Core.Security;

namespace PasswordVault.App.Views;

/// <summary>
/// Interaction logic for the main password vault window.
/// </summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly DispatcherTimer _idleTimer;

    public MainWindow(MainViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);

        InitializeComponent();
        _viewModel = viewModel;
        DataContext = _viewModel;

        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _idleTimer.Tick += OnIdleTimerTick;
        _idleTimer.Start();

        Closed += OnWindowClosed;
    }

    private async void CreateVaultButton_Click(object sender, RoutedEventArgs e)
    {
        await SubmitCreateVaultAsync();
    }

    private async void CreatePassphraseBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await SubmitCreateVaultAsync();
        }
    }

    private async void UnlockVaultButton_Click(object sender, RoutedEventArgs e)
    {
        await SubmitUnlockVaultAsync();
    }

    private async void UnlockPassphraseBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await SubmitUnlockVaultAsync();
        }
    }

    private void AddEntryButton_Click(object sender, RoutedEventArgs e)
    {
        SubmitAddEntry();
    }

    private void EntryPasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            SubmitAddEntry();
        }
    }

    private void ToggleRevealButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: VaultEntryViewModel entryVm })
        {
            _viewModel.ToggleRevealEntry(entryVm);
        }
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: VaultEntryViewModel entryVm })
        {
            _viewModel.CopyEntryPassword(entryVm);
        }
    }

    private void DeleteButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: VaultEntryViewModel entryVm })
        {
            _viewModel.DeleteEntry(entryVm);
        }
    }

    private void LockVaultButton_Click(object sender, RoutedEventArgs e)
    {
        ClearAllPasswordBoxes();
        _viewModel.LockVault();
    }

    private async Task SubmitCreateVaultAsync()
    {
        if (_viewModel.IsBusy)
        {
            return;
        }

        SecretBuffer master = SecureStringHelper.ToSecretBuffer(CreatePassphraseBox.SecurePassword);
        SecretBuffer confirm;
        try
        {
            confirm = SecureStringHelper.ToSecretBuffer(ConfirmPassphraseBox.SecurePassword);
        }
        catch
        {
            master.Dispose();
            throw;
        }
        finally
        {
            CreatePassphraseBox.Clear();
            ConfirmPassphraseBox.Clear();
        }

        await _viewModel.CreateVaultAsync(master, confirm);
    }

    private async Task SubmitUnlockVaultAsync()
    {
        if (_viewModel.IsBusy)
        {
            return;
        }

        SecretBuffer master;
        try
        {
            master = SecureStringHelper.ToSecretBuffer(UnlockPassphraseBox.SecurePassword);
        }
        finally
        {
            UnlockPassphraseBox.Clear();
        }

        await _viewModel.UnlockVaultAsync(master);
    }

    private void SubmitAddEntry()
    {
        SecretBuffer password;
        try
        {
            password = SecureStringHelper.ToSecretBuffer(EntryPasswordBox.SecurePassword);
        }
        finally
        {
            EntryPasswordBox.Clear();
        }

        _viewModel.AddEntry(password);
    }

    private void OnIdleTimerTick(object? sender, EventArgs e)
    {
        _viewModel.TickIdleTimer();
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        _idleTimer.Stop();
        _idleTimer.Tick -= OnIdleTimerTick;
        ClearAllPasswordBoxes();
        _viewModel.LockVault();
    }

    private void ClearAllPasswordBoxes()
    {
        CreatePassphraseBox.Clear();
        ConfirmPassphraseBox.Clear();
        UnlockPassphraseBox.Clear();
        EntryPasswordBox.Clear();
    }
}
