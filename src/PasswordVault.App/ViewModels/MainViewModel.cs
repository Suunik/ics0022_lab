using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using PasswordVault.App.Services;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;
using PasswordVault.Core.Session;

namespace PasswordVault.App.ViewModels;

/// <summary>
/// Coordinates vault creation, unlocking, entry management, idle locking, and clipboard hygiene.
/// </summary>
public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly VaultSession _session;
    private readonly IClipboardService _clipboardService;
    private readonly RelayCommand _lockCommand;

    private bool _isBusy;
    private string _statusMessage = "Enter a master passphrase to create or unlock your local vault.";
    private bool _isError;
    private string _idleTimeRemainingText = "Locked";
    private string _newSite = string.Empty;
    private string _newUsername = string.Empty;
    private bool _disposed;

    public MainViewModel(VaultSession session, IClipboardService clipboardService)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(clipboardService);

        _session = session;
        _clipboardService = clipboardService;
        _lockCommand = new RelayCommand(LockVault, () => IsUnlocked && !IsBusy);

        RefreshSessionProperties();
    }

    public ObservableCollection<VaultEntryViewModel> Entries { get; } = [];

    public RelayCommand LockCommand => _lockCommand;

    public string VaultPathText => _session.VaultPath;

    public bool IsVaultCreated => _session.VaultExists;

    public bool IsUnlocked => _session.IsUnlocked;

    public bool IsLocked => !IsUnlocked;

    public bool IsCreateMode => IsLocked && !IsVaultCreated;

    public bool IsUnlockMode => IsLocked && IsVaultCreated;

    public string LockBadgeText => IsUnlocked ? "Unlocked" : "Locked";

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(IsNotBusy));
                _lockCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsNotBusy => !IsBusy;

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public bool IsError
    {
        get => _isError;
        private set => SetProperty(ref _isError, value);
    }

    public string IdleTimeRemainingText
    {
        get => _idleTimeRemainingText;
        private set => SetProperty(ref _idleTimeRemainingText, value);
    }

    public string NewSite
    {
        get => _newSite;
        set => SetProperty(ref _newSite, value);
    }

    public string NewUsername
    {
        get => _newUsername;
        set => SetProperty(ref _newUsername, value);
    }

    public async Task CreateVaultAsync(SecretBuffer masterPassphrase, SecretBuffer confirmPassphrase)
    {
        ArgumentNullException.ThrowIfNull(masterPassphrase);
        ArgumentNullException.ThrowIfNull(confirmPassphrase);

        try
        {
            if (IsBusy)
            {
                return;
            }

            ReadOnlySpan<byte> masterSpan = masterPassphrase.AsReadOnlySpan();
            ReadOnlySpan<byte> confirmSpan = confirmPassphrase.AsReadOnlySpan();
            if (masterSpan.Length != confirmSpan.Length ||
                !CryptographicOperations.FixedTimeEquals(masterSpan, confirmSpan))
            {
                SetStatus("Master passphrases do not match.", isError: true);
                return;
            }

            IsBusy = true;
            SetStatus("Deriving key and creating encrypted vault...", isError: false);

            await Task.Run(() => _session.CreateVault(masterPassphrase.AsReadOnlySpan()));

            LoadEntriesFromSession();
            RefreshSessionProperties();
            SetStatus("Vault created and unlocked.", isError: false);
        }
        catch (VaultException ex)
        {
            HandleVaultException(ex);
        }
        finally
        {
            IsBusy = false;
            masterPassphrase.Dispose();
            confirmPassphrase.Dispose();
        }
    }

    public async Task UnlockVaultAsync(SecretBuffer masterPassphrase)
    {
        ArgumentNullException.ThrowIfNull(masterPassphrase);

        try
        {
            if (IsBusy)
            {
                return;
            }

            IsBusy = true;
            SetStatus("Verifying master passphrase...", isError: false);

            await Task.Run(() => _session.UnlockVault(masterPassphrase.AsReadOnlySpan()));

            LoadEntriesFromSession();
            RefreshSessionProperties();
            SetStatus("Vault unlocked.", isError: false);
        }
        catch (VaultException ex)
        {
            HandleVaultException(ex);
        }
        finally
        {
            IsBusy = false;
            masterPassphrase.Dispose();
        }
    }

    public void AddEntry(SecretBuffer password)
    {
        ArgumentNullException.ThrowIfNull(password);

        try
        {
            VaultEntrySummary summary = _session.AddEntry(NewSite, NewUsername, password.AsReadOnlySpan());
            Entries.Add(new VaultEntryViewModel(summary.Id, summary.Site, summary.Username));
            NewSite = string.Empty;
            NewUsername = string.Empty;
            RefreshSessionProperties();
            SetStatus($"Saved entry for {summary.Site}.", isError: false);
        }
        catch (VaultException ex)
        {
            HandleVaultException(ex);
        }
        finally
        {
            password.Dispose();
        }
    }

    public void ToggleRevealEntry(VaultEntryViewModel entryVm)
    {
        ArgumentNullException.ThrowIfNull(entryVm);

        if (entryVm.IsPasswordVisible)
        {
            entryVm.Hide();
            SetStatus($"Password hidden for {entryVm.Site}.", isError: false);
            return;
        }

        try
        {
            using SecretBuffer secret = _session.RevealPassword(entryVm.Id);
            entryVm.Reveal(secret.ToUtf8String());
            RefreshSessionProperties();
            SetStatus($"Revealed password for {entryVm.Site}.", isError: false);
        }
        catch (VaultException ex)
        {
            HandleVaultException(ex);
        }
    }

    public void CopyEntryPassword(VaultEntryViewModel entryVm)
    {
        ArgumentNullException.ThrowIfNull(entryVm);

        try
        {
            using SecretBuffer secret = _session.RevealPassword(entryVm.Id);
            _clipboardService.CopySecret(secret);
            RefreshSessionProperties();
            SetStatus($"Copied password for {entryVm.Site} (clipboard auto-clears in 30s).", isError: false);
        }
        catch (VaultException ex)
        {
            HandleVaultException(ex);
        }
    }

    public void DeleteEntry(VaultEntryViewModel entryVm)
    {
        ArgumentNullException.ThrowIfNull(entryVm);

        try
        {
            _session.DeleteEntry(entryVm.Id);
            entryVm.Hide();
            Entries.Remove(entryVm);
            RefreshSessionProperties();
            SetStatus($"Removed entry for {entryVm.Site}.", isError: false);
        }
        catch (VaultException ex)
        {
            HandleVaultException(ex);
        }
    }

    public void LockVault()
    {
        ClearVisibleEntries();
        NewSite = string.Empty;
        NewUsername = string.Empty;
        _clipboardService.ClearIfOwned();
        _session.Lock();
        RefreshSessionProperties();
        SetStatus("Vault locked and in-memory secrets wiped.", isError: false);
    }

    public void TickIdleTimer()
    {
        if (_disposed || !IsUnlocked)
        {
            IdleTimeRemainingText = "Locked";
            return;
        }

        if (_session.EnforceIdleTimeout())
        {
            ClearVisibleEntries();
            NewSite = string.Empty;
            NewUsername = string.Empty;
            _clipboardService.ClearIfOwned();
            RefreshSessionProperties();
            SetStatus("Vault locked automatically after 5 minutes of inactivity.", isError: true);
            return;
        }

        TimeSpan remaining = _session.RemainingIdleTime;
        IdleTimeRemainingText = string.Format(
            CultureInfo.InvariantCulture,
            "{0:D2}:{1:D2}",
            (int)remaining.TotalMinutes,
            remaining.Seconds);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        ClearVisibleEntries();
        _clipboardService.Dispose();
        _session.Dispose();
        _disposed = true;
    }

    private void LoadEntriesFromSession()
    {
        ClearVisibleEntries();
        foreach (VaultEntrySummary summary in _session.GetEntries())
        {
            Entries.Add(new VaultEntryViewModel(summary.Id, summary.Site, summary.Username));
        }
    }

    private void ClearVisibleEntries()
    {
        foreach (VaultEntryViewModel entry in Entries)
        {
            entry.Hide();
        }

        Entries.Clear();
    }

    private void HandleVaultException(VaultException ex)
    {
        if (ex is VaultLockedException)
        {
            ClearVisibleEntries();
            _clipboardService.ClearIfOwned();
        }

        RefreshSessionProperties();

        string safeMessage = ex switch
        {
            VaultAuthenticationException => "Unlock failed. Check your master passphrase.",
            VaultCorruptedException => "Vault integrity verification failed. The vault file may be corrupted or tampered with.",
            VaultStorageException => ex.Message,
            VaultValidationException => ex.Message,
            VaultCapacityException => ex.Message,
            VaultLockedException => ex.Message,
            _ => "A vault error occurred."
        };

        SetStatus(safeMessage, isError: true);
    }

    private void RefreshSessionProperties()
    {
        OnPropertyChanged(nameof(IsVaultCreated));
        OnPropertyChanged(nameof(IsUnlocked));
        OnPropertyChanged(nameof(IsLocked));
        OnPropertyChanged(nameof(IsCreateMode));
        OnPropertyChanged(nameof(IsUnlockMode));
        OnPropertyChanged(nameof(LockBadgeText));
        _lockCommand.RaiseCanExecuteChanged();
        TickIdleTimer();
    }

    private void SetStatus(string message, bool isError)
    {
        IsError = isError;
        StatusMessage = message;
    }
}
