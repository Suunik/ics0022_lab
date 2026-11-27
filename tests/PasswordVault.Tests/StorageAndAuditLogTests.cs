using System.Text;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;
using PasswordVault.Core.Session;
using PasswordVault.Core.Storage;

namespace PasswordVault.Tests;

[TestClass]
public sealed class StorageAndAuditLogTests
{
    private string _tempDir = string.Empty;
    private FileVaultStorage _storage = null!;
    private FileAuditLog _auditLog = null!;
    private FakeClock _clock = null!;
    private FakeUserIdentityProvider _identity = null!;

    [TestInitialize]
    public void Initialize()
    {
        _tempDir = TestHarness.CreateTempDirectory();
        _identity = new FakeUserIdentityProvider();
        _storage = new FileVaultStorage(_tempDir);
        _auditLog = new FileAuditLog(_tempDir, _identity);
        _clock = new FakeClock();
    }

    [TestCleanup]
    public void Cleanup()
    {
        TestHarness.DeleteDirectorySafe(_tempDir);
    }

    [TestMethod]
    public void DuplicateVaultCreationIsRejectedWithoutOverwritingExistingVault()
    {
        byte[] master = TestHarness.CreateSampleMasterBytes();
        byte[] secret = TestHarness.CreateSampleSecretBytes("keep-me");

        using (VaultSession session = CreateSession())
        {
            session.CreateVault(master);
            session.AddEntry("keep.example", "alice", secret);
        }

        using (VaultSession duplicateSession = CreateSession())
        {
            Assert.ThrowsExactly<VaultStorageException>(() => duplicateSession.CreateVault(master));
            duplicateSession.UnlockVault(master);
            Assert.HasCount(1, duplicateSession.GetEntries());
        }
    }

    [TestMethod]
    public void TamperedVaultAclIsRejectedOnUnlock()
    {
        byte[] master = TestHarness.CreateSampleMasterBytes();
        using (VaultSession session = CreateSession())
        {
            session.CreateVault(master);
        }

        TestHarness.GrantEveryoneReadAcl(_storage.GetVaultPath("mainvault"));

        using VaultSession tamperedSession = CreateSession();
        Assert.ThrowsExactly<VaultStorageException>(() => tamperedSession.UnlockVault(master));
        Assert.IsFalse(tamperedSession.IsUnlocked);
    }

    [TestMethod]
    public void ExternalModificationOnDiskIsDetectedBeforeOverwrite()
    {
        byte[] master = TestHarness.CreateSampleMasterBytes();
        using VaultSession session = CreateSession();
        session.CreateVault(master);

        string vaultPath = _storage.GetVaultPath("mainvault");
        byte[] raw = File.ReadAllBytes(vaultPath);
        raw[^1] ^= 0xFF;
        File.WriteAllBytes(vaultPath, raw);

        Assert.ThrowsExactly<VaultStorageException>(
            () => session.AddEntry("site.test", "user.test", TestHarness.CreateSampleSecretBytes("race")));
    }

    [TestMethod]
    public void AuditLogRecordsEventsWithoutSecretsAndTamperedLogAclLocksSession()
    {
        byte[] master = TestHarness.CreateSampleMasterBytes(1);
        byte[] wrongMaster = TestHarness.CreateSampleMasterBytes(2);
        byte[] entrySecret = TestHarness.CreateSampleSecretBytes("audit-secret");

        using (VaultSession session = CreateSession())
        {
            session.CreateVault(master);
            session.AddEntry("example.com", "secret-username-not-logged", entrySecret);
            session.Lock();

            Assert.ThrowsExactly<VaultAuthenticationException>(() => session.UnlockVault(wrongMaster));
            Assert.ThrowsExactly<VaultLockedException>(() => session.GetEntries());
        }

        string logContent = File.ReadAllText(_auditLog.LogPath, Encoding.UTF8);
        StringAssert.Contains(logContent, "event=Create", StringComparison.Ordinal);
        StringAssert.Contains(logContent, "event=AddEntry", StringComparison.Ordinal);
        StringAssert.Contains(logContent, "event=Lock", StringComparison.Ordinal);
        StringAssert.Contains(logContent, "event=Unlock record_id=- outcome=Failure", StringComparison.Ordinal);
        StringAssert.Contains(logContent, "event=AccessDenied", StringComparison.Ordinal);

        // Neither master passphrase, entry secret, nor entry username should appear in pwm.log.
        Assert.IsFalse(logContent.Contains(Encoding.UTF8.GetString(master), StringComparison.Ordinal));
        Assert.IsFalse(logContent.Contains(Encoding.UTF8.GetString(entrySecret), StringComparison.Ordinal));
        Assert.IsFalse(logContent.Contains("secret-username-not-logged", StringComparison.Ordinal));

        // Granting Everyone access to pwm.log must fail UnlockVault and leave the session locked.
        TestHarness.GrantEveryoneReadAcl(_auditLog.LogPath);
        using VaultSession tamperedLogSession = CreateSession();
        Assert.ThrowsExactly<VaultStorageException>(() => tamperedLogSession.UnlockVault(master));
        Assert.IsFalse(tamperedLogSession.IsUnlocked);
    }

    private VaultSession CreateSession()
    {
        return new VaultSession(
            "mainvault",
            _storage,
            _auditLog,
            _clock,
            _identity,
            VaultSession.DefaultIdleTimeout,
            TestHarness.FastTestKdf);
    }
}
