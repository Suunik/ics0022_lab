using System.Security.Principal;
using PasswordVault.Core.Models;

namespace PasswordVault.Core.Session;

/// <summary>
/// Resolves the current Windows user SID via <see cref="WindowsIdentity"/>.
/// </summary>
public sealed class WindowsUserIdentityProvider : IUserIdentityProvider
{
    public string GetCurrentUserIdentifier()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value
            ?? throw new VaultStorageException("Unable to resolve current Windows user SID.");
    }
}
