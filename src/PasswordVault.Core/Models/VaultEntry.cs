using PasswordVault.Core.Security;

namespace PasswordVault.Core.Models;

/// <summary>
/// Represents an in-memory credential entry whose password is kept in a zeroizable <see cref="SecretBuffer"/>.
/// </summary>
public sealed class VaultEntry : IDisposable
{
    public VaultEntry(ulong id, string site, string username, SecretBuffer password)
    {
        ArgumentOutOfRangeException.ThrowIfZero(id);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);

        Id = id;
        Site = site;
        Username = username;
        Password = password;
    }

    public ulong Id { get; }

    public string Site { get; }

    public string Username { get; }

    public SecretBuffer Password { get; }

    /// <summary>
    /// Returns a non-secret summary projection of this entry.
    /// </summary>
    public VaultEntrySummary ToSummary() => new(Id, Site, Username);

    /// <inheritdoc />
    public void Dispose()
    {
        Password.Dispose();
    }
}
