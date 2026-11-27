using System.Security.Cryptography;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;

namespace PasswordVault.Core.Storage;

/// <summary>
/// Persists encrypted vault files atomically under a user-private directory with ACL and reparse-point checks.
/// </summary>
public sealed class FileVaultStorage : IVaultStorage
{
    private const string VaultFileExtension = ".vault";
    private const string LockFileName = ".vault.lock";
    private readonly Lock _syncLock = new();

    public FileVaultStorage(string? baseDirectory = null)
    {
        BaseDirectory = Path.GetFullPath(baseDirectory ?? GetDefaultVaultDirectory());
    }

    public string BaseDirectory { get; }

    /// <summary>
    /// Returns the default user-local application data directory outside any source repository.
    /// </summary>
    public static string GetDefaultVaultDirectory()
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localAppData, "SecurePasswordVault");
    }

    /// <inheritdoc />
    public string GetVaultPath(string vaultName)
    {
        string validated = InputValidator.ValidateVaultName(vaultName);
        return Path.Combine(BaseDirectory, validated + VaultFileExtension);
    }

    /// <inheritdoc />
    public bool Exists(string vaultName)
    {
        string vaultPath = GetVaultPath(vaultName);
        return File.Exists(vaultPath);
    }

    /// <inheritdoc />
    public byte[] ReadVault(string vaultName, out byte[] sha256Hash)
    {
        string vaultPath = GetVaultPath(vaultName);

        lock (_syncLock)
        {
            WindowsAclHelper.EnsureDirectorySecure(BaseDirectory);

            if (!File.Exists(vaultPath))
            {
                throw new VaultStorageException("Vault file does not exist.");
            }

            WindowsAclHelper.VerifyFileAcl(vaultPath);
            byte[] bytes = ReadBoundedVaultBytes(vaultPath);
            sha256Hash = SHA256.HashData(bytes);
            return bytes;
        }
    }

    /// <inheritdoc />
    public byte[] CreateVault(string vaultName, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateVaultPayloadLength(data.Length);

        string vaultPath = GetVaultPath(vaultName);

        lock (_syncLock)
        {
            WindowsAclHelper.EnsureDirectorySecure(BaseDirectory);
            using FileStream lockStream = AcquireDirectoryLock();

            if (File.Exists(vaultPath))
            {
                throw new VaultStorageException("Vault already exists and cannot be overwritten on create.");
            }

            return WriteTempFileAndMove(vaultPath, data, overwrite: false, expectedCurrentHash: ReadOnlySpan<byte>.Empty);
        }
    }

    /// <inheritdoc />
    public byte[] ReplaceVault(string vaultName, byte[] data, ReadOnlySpan<byte> expectedCurrentHash)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateVaultPayloadLength(data.Length);

        if (expectedCurrentHash.Length != 32)
        {
            throw new ArgumentException("Expected SHA-256 hash must be 32 bytes.", nameof(expectedCurrentHash));
        }

        string vaultPath = GetVaultPath(vaultName);

        lock (_syncLock)
        {
            WindowsAclHelper.EnsureDirectorySecure(BaseDirectory);
            using FileStream lockStream = AcquireDirectoryLock();

            if (!File.Exists(vaultPath))
            {
                throw new VaultStorageException("Target vault file no longer exists.");
            }

            WindowsAclHelper.VerifyFileAcl(vaultPath);
            byte[] currentBytes = ReadBoundedVaultBytes(vaultPath);
            byte[] actualHash = SHA256.HashData(currentBytes);

            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedCurrentHash))
            {
                throw new VaultStorageException("Vault file on disk was modified externally.");
            }

            return WriteTempFileAndMove(vaultPath, data, overwrite: true, expectedCurrentHash);
        }
    }

    private FileStream AcquireDirectoryLock()
    {
        string lockPath = Path.Combine(BaseDirectory, LockFileName);
        if (File.Exists(lockPath))
        {
            WindowsAclHelper.EnsureNotReparsePoint(lockPath);
        }

        FileStream stream = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            WindowsAclHelper.ApplyOwnerOnlyFileAcl(lockPath);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private byte[] WriteTempFileAndMove(
        string vaultPath,
        byte[] data,
        bool overwrite,
        ReadOnlySpan<byte> expectedCurrentHash)
    {
        _ = expectedCurrentHash;
        string tempName = $".init-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))}.tmp";
        string tempPath = Path.Combine(BaseDirectory, tempName);

        try
        {
            using (FileStream tempStream = new(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough))
            {
                WindowsAclHelper.ApplyOwnerOnlyFileAcl(tempPath);
                tempStream.Write(data, 0, data.Length);
                tempStream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, vaultPath, overwrite);
            WindowsAclHelper.VerifyFileAcl(vaultPath);
            return SHA256.HashData(data);
        }
        catch
        {
            DeleteTempFileBestEffort(tempPath);
            throw;
        }
    }

    private static byte[] ReadBoundedVaultBytes(string vaultPath)
    {
        FileInfo fileInfo = new(vaultPath);
        if (fileInfo.Length < VaultCrypto.MinVaultBytes || fileInfo.Length > VaultCrypto.MaxVaultBytes)
        {
            throw new VaultCorruptedException("Vault file size is outside valid bounds.");
        }

        using FileStream stream = new(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length < VaultCrypto.MinVaultBytes || stream.Length > VaultCrypto.MaxVaultBytes)
        {
            throw new VaultCorruptedException("Vault file size is outside valid bounds.");
        }

        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }

    private static void ValidateVaultPayloadLength(int length)
    {
        if (length < VaultCrypto.MinVaultBytes || length > VaultCrypto.MaxVaultBytes)
        {
            throw new VaultCapacityException("Encrypted vault size is outside allowed bounds.");
        }
    }

    private static void DeleteTempFileBestEffort(string tempPath)
    {
        try
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
        catch (IOException)
        {
            // Best-effort cleanup of temporary file; original exception takes precedence.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort cleanup of temporary file; original exception takes precedence.
        }
    }
}
