namespace PasswordVault.Core.Storage;

/// <summary>
/// Abstraction for atomic, permission-checked encrypted vault persistence.
/// </summary>
public interface IVaultStorage
{
    string BaseDirectory { get; }

    string GetVaultPath(string vaultName);

    bool Exists(string vaultName);

    byte[] ReadVault(string vaultName, out byte[] sha256Hash);

    byte[] CreateVault(string vaultName, byte[] data);

    byte[] ReplaceVault(string vaultName, byte[] data, ReadOnlySpan<byte> expectedCurrentHash);
}
