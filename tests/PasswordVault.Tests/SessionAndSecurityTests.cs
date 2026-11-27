using System.Security.Cryptography;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;
using PasswordVault.Core.Session;
using PasswordVault.Core.Storage;

namespace PasswordVault.Tests;

[TestClass]
public sealed class SessionAndSecurityTests
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
    public void CreateAddReopenAndVerifyWrongPassphrasePreservesVaultFile()
    {
        byte[] correctMaster = TestHarness.CreateSampleMasterBytes(1);
        byte[] wrongMaster = TestHarness.CreateSampleMasterBytes(2);
        byte[] secretBytes = TestHarness.CreateSampleSecretBytes("workshop-entry");

        using (VaultSession session = CreateSession())
        {
            session.CreateVault(correctMaster);
            VaultEntrySummary created = session.AddEntry("https://portal.taltech.ee", "student01", secretBytes);
            Assert.AreEqual("https://portal.taltech.ee", created.Site);
            session.Lock();
            Assert.IsFalse(session.IsUnlocked);
        }

        string vaultPath = _storage.GetVaultPath("mainvault");
        byte[] originalBytes = File.ReadAllBytes(vaultPath);
        byte[] originalHash = SHA256.HashData(originalBytes);

        // Wrong passphrase must fail and leave the saved vault file byte-for-byte identical.
        using (VaultSession session = CreateSession())
        {
            Assert.ThrowsExactly<VaultAuthenticationException>(() => session.UnlockVault(wrongMaster));
            Assert.IsFalse(session.IsUnlocked);

            byte[] afterFailedBytes = File.ReadAllBytes(vaultPath);
            byte[] afterFailedHash = SHA256.HashData(afterFailedBytes);
            Assert.IsTrue(originalHash.SequenceEqual(afterFailedHash));

            // Reopen with correct passphrase succeeds and preserves the entry.
            session.UnlockVault(correctMaster);
            IReadOnlyList<VaultEntrySummary> entries = session.GetEntries();
            Assert.HasCount(1, entries);
            Assert.AreEqual("https://portal.taltech.ee", entries[0].Site);
            Assert.AreEqual("student01", entries[0].Username);

            using SecretBuffer revealed = session.RevealPassword(entries[0].Id);
            Assert.IsTrue(revealed.AsReadOnlySpan().SequenceEqual(secretBytes));
        }
    }

    [TestMethod]
    public void LockedSessionAndIdleTimeoutAndIdentityMismatchRefuseAccess()
    {
        byte[] master = TestHarness.CreateSampleMasterBytes();
        using VaultSession session = CreateSession();

        Assert.ThrowsExactly<VaultLockedException>(() => session.GetEntries());
        Assert.ThrowsExactly<VaultLockedException>(
            () => session.AddEntry("s", "u", TestHarness.CreateSampleSecretBytes("locked")));

        session.CreateVault(master);
        VaultEntrySummary summary = session.AddEntry("a.com", "u1", TestHarness.CreateSampleSecretBytes("idle"));

        // Advance monotonic clock past 5 minutes -> next access locks and refuses.
        _clock.Advance(VaultSession.DefaultIdleTimeout + TimeSpan.FromSeconds(1));
        Assert.ThrowsExactly<VaultLockedException>(() => session.GetEntries());
        Assert.IsFalse(session.IsUnlocked);

        // Unlock again and simulate Windows identity mismatch -> locks and refuses.
        session.UnlockVault(master);
        _identity.CurrentSid = "S-1-5-21-999999-999999-999999-500";
        Assert.ThrowsExactly<VaultLockedException>(() => session.RevealPassword(summary.Id));
        Assert.IsFalse(session.IsUnlocked);
    }

    [TestMethod]
    public void UpdateDeleteAndCapacityLimitKeepVaultConsistent()
    {
        byte[] master = TestHarness.CreateSampleMasterBytes();
        byte[] initialSecret = TestHarness.CreateSampleSecretBytes("init");
        byte[] updatedSecret = TestHarness.CreateSampleSecretBytes("updated");

        using (VaultSession session = CreateSession())
        {
            session.CreateVault(master);
            VaultEntrySummary first = session.AddEntry("site1.org", "user1", initialSecret);
            VaultEntrySummary second = session.AddEntry("site2.org", "user2", initialSecret);

            VaultEntrySummary updated = session.UpdateEntry(first.Id, "site1.net", "user1b", updatedSecret);
            Assert.AreEqual("site1.net", updated.Site);
            Assert.AreEqual("user1b", updated.Username);

            session.DeleteEntry(second.Id);

            // Fill near 64 KiB limit with 4094-byte passwords until capacity error occurs.
            byte[] largeSecret = new byte[InputValidator.MaxEntryPasswordBytes];
            Array.Fill(largeSecret, (byte)'A');
            int addedBulk = 0;
            bool hitCapacity = false;

            for (int i = 0; i < 20; i++)
            {
                try
                {
                    session.AddEntry($"bulk-{i}.example", "bulk-user", largeSecret);
                    addedBulk++;
                }
                catch (VaultCapacityException)
                {
                    hitCapacity = true;
                    break;
                }
            }

            Assert.IsTrue(hitCapacity);
            Assert.HasCount(1 + addedBulk, session.GetEntries());
        }

        // Reopen and confirm updated entry and bulk entries remain intact.
        using (VaultSession reopened = CreateSession())
        {
            reopened.UnlockVault(master);
            IReadOnlyList<VaultEntrySummary> items = reopened.GetEntries();
            Assert.IsGreaterThan(1, items.Count);
            Assert.AreEqual("site1.net", items[0].Site);

            using SecretBuffer revealed = reopened.RevealPassword(items[0].Id);
            Assert.IsTrue(revealed.AsReadOnlySpan().SequenceEqual(updatedSecret));
        }
    }

    [TestMethod]
    public void SecretBufferZeroesMemoryOnDisposeAndRedactsToString()
    {
        byte[] raw = TestHarness.CreateSampleSecretBytes("wipe-check");
        SecretBuffer buffer = SecretBuffer.CopyFrom(raw);
        Span<byte> internalSpan = buffer.AsSpan();

        Assert.AreEqual("[REDACTED]", buffer.ToString());
        Assert.IsTrue(internalSpan.SequenceEqual(raw));

        buffer.Dispose();
        Assert.IsTrue(internalSpan.ToArray().All(static b => b == 0));
        Assert.ThrowsExactly<ObjectDisposedException>(() => _ = buffer.Length);
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
