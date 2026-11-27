using System.Security.Cryptography;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;
using PasswordVault.Core.Storage;

namespace PasswordVault.Core.Session;

/// <summary>
/// Manages the authenticated vault lifecycle, in-memory secret wiping, access control, and atomic persistence.
/// </summary>
public sealed class VaultSession : IDisposable
{
    public static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromMinutes(5);

    private readonly string _vaultName;
    private readonly IVaultStorage _storage;
    private readonly IAuditLog _auditLog;
    private readonly IUserIdentityProvider _identityProvider;
    private readonly VaultKdfParameters _kdfParameters;
    private readonly IdleTimer _idleTimer;
    private readonly List<VaultEntry> _entries = [];

    private SecretBuffer? _encryptionKey;
    private VaultHeader? _header;
    private byte[]? _lastDiskHash;
    private string? _unlockedUserSid;
    private ulong _nextEntryId = 1;
    private bool _disposed;

    public VaultSession(
        string vaultName,
        IVaultStorage storage,
        IAuditLog auditLog,
        IClock? clock = null,
        IUserIdentityProvider? identityProvider = null,
        TimeSpan? idleTimeout = null,
        VaultKdfParameters? kdfParameters = null)
    {
        _vaultName = InputValidator.ValidateVaultName(vaultName);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(auditLog);

        _storage = storage;
        _auditLog = auditLog;
        _identityProvider = identityProvider ?? new WindowsUserIdentityProvider();
        _kdfParameters = kdfParameters ?? VaultKdfParameters.Default;
        _idleTimer = new IdleTimer(clock ?? new SystemClock(), idleTimeout ?? DefaultIdleTimeout);
    }

    public string VaultName => _vaultName;

    public string VaultPath => _storage.GetVaultPath(_vaultName);

    public bool VaultExists => _storage.Exists(_vaultName);

    public bool IsUnlocked => !_disposed && _encryptionKey is not null;

    public TimeSpan RemainingIdleTime => IsUnlocked ? _idleTimer.Remaining : TimeSpan.Zero;

    /// <summary>
    /// Creates a new encrypted vault protected by <paramref name="masterPassphraseUtf8"/> and unlocks the session.
    /// </summary>
    public void CreateVault(ReadOnlySpan<byte> masterPassphraseUtf8)
    {
        ThrowIfDisposed();
        LockCore(emitAudit: false);

        InputValidator.ValidateNewMasterPassphrase(masterPassphraseUtf8);

        if (_storage.Exists(_vaultName))
        {
            _auditLog.Record(_vaultName, AuditEvent.Create, AuditOutcome.Failure);
            throw new VaultStorageException("Vault already exists.");
        }

        Span<byte> salt = stackalloc byte[VaultHeader.SaltSize];
        RandomNumberGenerator.Fill(salt);
        Span<byte> initialNonce = stackalloc byte[VaultHeader.NonceSize];

        (SecretBuffer encryptionKey, byte[] verifier) =
            VaultKeyDerivation.DeriveKeyAndVerifier(masterPassphraseUtf8, salt, _kdfParameters);

        try
        {
            VaultHeader headerTemplate = new(
                _kdfParameters.MemoryKiB,
                _kdfParameters.Iterations,
                _kdfParameters.Parallelism,
                salt,
                verifier,
                initialNonce);

            using SecretBuffer plaintext = VaultSerializer.Serialize(_entries);
            (byte[] vaultBytes, VaultHeader finalHeader) =
                VaultCrypto.Encrypt(headerTemplate, _vaultName, encryptionKey, plaintext.AsReadOnlySpan());

            byte[] diskHash = _storage.CreateVault(_vaultName, vaultBytes);

            _encryptionKey = encryptionKey;
            _header = finalHeader;
            _lastDiskHash = diskHash;
            _unlockedUserSid = _identityProvider.GetCurrentUserIdentifier();
            _nextEntryId = 1;
            _idleTimer.Reset();
        }
        catch
        {
            encryptionKey.Dispose();
            throw;
        }

        try
        {
            _auditLog.Record(_vaultName, AuditEvent.Create, AuditOutcome.Success);
        }
        catch
        {
            LockCore(emitAudit: false);
            throw;
        }
    }

    /// <summary>
    /// Verifies <paramref name="masterPassphraseUtf8"/>, decrypts the vault, and activates the session.
    /// </summary>
    public void UnlockVault(ReadOnlySpan<byte> masterPassphraseUtf8)
    {
        ThrowIfDisposed();
        LockCore(emitAudit: false);

        try
        {
            InputValidator.ValidateUnlockMasterPassphrase(masterPassphraseUtf8);
        }
        catch
        {
            RecordSafeAudit(AuditEvent.Unlock, AuditOutcome.Failure);
            throw;
        }

        byte[] vaultBytes;
        byte[] diskHash;
        VaultHeader header;
        try
        {
            vaultBytes = _storage.ReadVault(_vaultName, out diskHash);
            header = VaultHeader.Parse(vaultBytes);
        }
        catch
        {
            RecordSafeAudit(AuditEvent.Unlock, AuditOutcome.Failure);
            throw;
        }

        VaultKdfParameters headerKdf = new(header.MemoryKiB, header.Iterations, header.Parallelism);
        (SecretBuffer encryptionKey, byte[] computedVerifier) =
            VaultKeyDerivation.DeriveKeyAndVerifier(masterPassphraseUtf8, header.Salt, headerKdf);

        if (!VaultKeyDerivation.VerifyVerifier(header.Verifier, computedVerifier))
        {
            encryptionKey.Dispose();
            RecordSafeAudit(AuditEvent.Unlock, AuditOutcome.Failure);
            throw new VaultAuthenticationException("Invalid master passphrase.");
        }

        List<VaultEntry> loadedEntries;
        try
        {
            using SecretBuffer plaintext = VaultCrypto.Decrypt(vaultBytes, _vaultName, encryptionKey, header);
            loadedEntries = VaultSerializer.Deserialize(plaintext.AsReadOnlySpan());
        }
        catch
        {
            encryptionKey.Dispose();
            RecordSafeAudit(AuditEvent.Unlock, AuditOutcome.Failure);
            throw;
        }

        _encryptionKey = encryptionKey;
        _header = header;
        _lastDiskHash = diskHash;
        _entries.AddRange(loadedEntries);
        _unlockedUserSid = _identityProvider.GetCurrentUserIdentifier();
        _nextEntryId = ComputeNextEntryId(_entries);
        _idleTimer.Reset();

        try
        {
            _auditLog.Record(_vaultName, AuditEvent.Unlock, AuditOutcome.Success);
        }
        catch
        {
            LockCore(emitAudit: false);
            throw;
        }
    }

    /// <summary>
    /// Locks the session if the inactivity timeout has elapsed and returns <see langword="true"/> when locked.
    /// </summary>
    public bool EnforceIdleTimeout()
    {
        if (!IsUnlocked || !_idleTimer.IsExpired)
        {
            return false;
        }

        LockCore(emitAudit: true);
        return true;
    }

    /// <summary>
    /// Returns non-secret summaries for all saved entries in the unlocked vault.
    /// </summary>
    public IReadOnlyList<VaultEntrySummary> GetEntries()
    {
        AuthorizeAccess();
        return _entries.Select(static entry => entry.ToSummary()).ToList();
    }

    /// <summary>
    /// Returns an independent <see cref="SecretBuffer"/> copy of the password for <paramref name="entryId"/>.
    /// </summary>
    public SecretBuffer RevealPassword(ulong entryId)
    {
        AuthorizeAccess();
        VaultEntry entry = FindEntryOrThrow(entryId);
        SecretBuffer copy = entry.Password.Clone();
        _auditLog.Record(_vaultName, AuditEvent.RevealPassword, AuditOutcome.Success, entryId);
        return copy;
    }

    /// <summary>
    /// Adds a new credential entry and atomically persists the updated encrypted vault.
    /// </summary>
    public VaultEntrySummary AddEntry(string site, string username, ReadOnlySpan<byte> passwordUtf8)
    {
        AuthorizeAccess();

        string validSite = InputValidator.ValidateSite(site);
        string validUsername = InputValidator.ValidateUsername(username);
        InputValidator.ValidateEntryPassword(passwordUtf8);

        ulong newId = _nextEntryId;
        SecretBuffer passwordBuffer = SecretBuffer.CopyFrom(passwordUtf8);
        VaultEntry newEntry;
        try
        {
            newEntry = new VaultEntry(newId, validSite, validUsername, passwordBuffer);
        }
        catch
        {
            passwordBuffer.Dispose();
            throw;
        }

        try
        {
            List<VaultEntry> candidateEntries = [.. _entries, newEntry];
            PersistCandidateEntries(candidateEntries);

            _entries.Add(newEntry);
            _nextEntryId = newId + 1;
            _auditLog.Record(_vaultName, AuditEvent.AddEntry, AuditOutcome.Success, newId);
            return newEntry.ToSummary();
        }
        catch
        {
            newEntry.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Updates an existing credential entry and atomically persists the updated encrypted vault.
    /// </summary>
    public VaultEntrySummary UpdateEntry(ulong entryId, string site, string username, ReadOnlySpan<byte> passwordUtf8)
    {
        AuthorizeAccess();

        int index = FindEntryIndexOrThrow(entryId);
        string validSite = InputValidator.ValidateSite(site);
        string validUsername = InputValidator.ValidateUsername(username);
        InputValidator.ValidateEntryPassword(passwordUtf8);

        SecretBuffer passwordBuffer = SecretBuffer.CopyFrom(passwordUtf8);
        VaultEntry updatedEntry;
        try
        {
            updatedEntry = new VaultEntry(entryId, validSite, validUsername, passwordBuffer);
        }
        catch
        {
            passwordBuffer.Dispose();
            throw;
        }

        try
        {
            List<VaultEntry> candidateEntries = [.. _entries];
            candidateEntries[index] = updatedEntry;
            PersistCandidateEntries(candidateEntries);

            VaultEntry previous = _entries[index];
            _entries[index] = updatedEntry;
            previous.Dispose();

            _auditLog.Record(_vaultName, AuditEvent.UpdateEntry, AuditOutcome.Success, entryId);
            return updatedEntry.ToSummary();
        }
        catch
        {
            updatedEntry.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Deletes an entry by identifier and atomically persists the updated encrypted vault.
    /// </summary>
    public void DeleteEntry(ulong entryId)
    {
        AuthorizeAccess();

        int index = FindEntryIndexOrThrow(entryId);
        List<VaultEntry> candidateEntries = [.. _entries];
        candidateEntries.RemoveAt(index);

        PersistCandidateEntries(candidateEntries);

        VaultEntry removed = _entries[index];
        _entries.RemoveAt(index);
        removed.Dispose();

        _auditLog.Record(_vaultName, AuditEvent.DeleteEntry, AuditOutcome.Success, entryId);
    }

    /// <summary>
    /// Immediately locks the vault and wipes all in-memory keys and entry passwords.
    /// </summary>
    public void Lock()
    {
        if (_disposed || !IsUnlocked)
        {
            return;
        }

        LockCore(emitAudit: true);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (IsUnlocked)
        {
            LockCore(emitAudit: true);
        }
        else
        {
            LockCore(emitAudit: false);
        }

        _disposed = true;
    }

    private void AuthorizeAccess()
    {
        ThrowIfDisposed();

        if (_encryptionKey is null || _header is null || _lastDiskHash is null)
        {
            RecordSafeAudit(AuditEvent.AccessDenied, AuditOutcome.Denied);
            throw new VaultLockedException("Vault is locked.");
        }

        if (_idleTimer.IsExpired)
        {
            LockCore(emitAudit: true);
            RecordSafeAudit(AuditEvent.AccessDenied, AuditOutcome.Denied);
            throw new VaultLockedException("Vault session expired due to inactivity.");
        }

        string currentSid = _identityProvider.GetCurrentUserIdentifier();
        if (!string.Equals(_unlockedUserSid, currentSid, StringComparison.Ordinal))
        {
            LockCore(emitAudit: false);
            RecordSafeAudit(AuditEvent.AccessDenied, AuditOutcome.Denied);
            throw new VaultLockedException("Windows user identity mismatch.");
        }

        _idleTimer.Reset();
    }

    private void PersistCandidateEntries(IReadOnlyList<VaultEntry> candidateEntries)
    {
        SecretBuffer key = _encryptionKey ?? throw new VaultLockedException("Vault is locked.");
        VaultHeader currentHeader = _header ?? throw new VaultLockedException("Vault is locked.");
        byte[] currentHash = _lastDiskHash ?? throw new VaultLockedException("Vault is locked.");

        using SecretBuffer plaintext = VaultSerializer.Serialize(candidateEntries);
        (byte[] vaultBytes, VaultHeader updatedHeader) =
            VaultCrypto.Encrypt(currentHeader, _vaultName, key, plaintext.AsReadOnlySpan());

        byte[] newHash = _storage.ReplaceVault(_vaultName, vaultBytes, currentHash);
        _header = updatedHeader;
        _lastDiskHash = newHash;
    }

    private VaultEntry FindEntryOrThrow(ulong entryId)
    {
        int index = FindEntryIndexOrThrow(entryId);
        return _entries[index];
    }

    private int FindEntryIndexOrThrow(ulong entryId)
    {
        for (int i = 0; i < _entries.Count; i++)
        {
            if (_entries[i].Id == entryId)
            {
                return i;
            }
        }

        throw new VaultValidationException("Requested entry was not found.");
    }

    private static ulong ComputeNextEntryId(IReadOnlyList<VaultEntry> entries)
    {
        ulong maxId = 0;
        foreach (VaultEntry entry in entries)
        {
            if (entry.Id > maxId)
            {
                maxId = entry.Id;
            }
        }

        return checked(maxId + 1);
    }

    private void LockCore(bool emitAudit)
    {
        foreach (VaultEntry entry in _entries)
        {
            entry.Dispose();
        }

        _entries.Clear();
        _encryptionKey?.Dispose();
        _encryptionKey = null;
        _header = null;
        _unlockedUserSid = null;
        _nextEntryId = 1;

        if (_lastDiskHash is not null)
        {
            CryptographicOperations.ZeroMemory(_lastDiskHash);
            _lastDiskHash = null;
        }

        if (emitAudit)
        {
            RecordSafeAudit(AuditEvent.Lock, AuditOutcome.Success);
        }
    }

    private void RecordSafeAudit(AuditEvent auditEvent, AuditOutcome outcome)
    {
        try
        {
            _auditLog.Record(_vaultName, auditEvent, outcome);
        }
        catch (VaultStorageException)
        {
            // Keep original authentication/lockout failure intact if audit log check fails on denial path.
        }
        catch (IOException)
        {
            // Keep original authentication/lockout failure intact if audit log write fails on denial path.
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
