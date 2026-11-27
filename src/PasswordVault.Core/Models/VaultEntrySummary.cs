namespace PasswordVault.Core.Models;

/// <summary>
/// Non-secret summary view of a stored credential entry.
/// </summary>
public sealed record VaultEntrySummary(ulong Id, string Site, string Username);
