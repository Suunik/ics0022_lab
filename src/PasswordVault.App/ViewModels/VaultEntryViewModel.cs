namespace PasswordVault.App.ViewModels;

/// <summary>
/// Presentation wrapper for a single vault credential row, masked by default.
/// </summary>
public sealed class VaultEntryViewModel : ObservableObject
{
    public static readonly string MaskedPlaceholder = new('\u2022', 12);

    private string _displayPassword = MaskedPlaceholder;
    private bool _isPasswordVisible;

    public VaultEntryViewModel(ulong id, string site, string username)
    {
        Id = id;
        Site = site;
        Username = username;
    }

    public ulong Id { get; }

    public string Site { get; }

    public string Username { get; }

    public string DisplayPassword
    {
        get => _displayPassword;
        private set => SetProperty(ref _displayPassword, value);
    }

    public bool IsPasswordVisible
    {
        get => _isPasswordVisible;
        private set
        {
            if (SetProperty(ref _isPasswordVisible, value))
            {
                OnPropertyChanged(nameof(ToggleVisibilityText));
            }
        }
    }

    public string ToggleVisibilityText => IsPasswordVisible ? "Hide" : "Show";

    public void Reveal(string passwordText)
    {
        DisplayPassword = passwordText;
        IsPasswordVisible = true;
    }

    public void Hide()
    {
        DisplayPassword = MaskedPlaceholder;
        IsPasswordVisible = false;
    }
}
