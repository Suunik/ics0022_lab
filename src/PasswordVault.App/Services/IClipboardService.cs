using PasswordVault.Core.Security;

namespace PasswordVault.App.Services;

/// <summary>
/// Manages copying secret passwords to the clipboard and clearing them automatically.
/// </summary>
public interface IClipboardService : IDisposable
{
    void CopySecret(SecretBuffer secret);

    void ClearIfOwned();
}
