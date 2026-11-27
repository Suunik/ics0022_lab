using System.Security.Cryptography;
using System.Text;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;

namespace PasswordVault.Tests;

[TestClass]
public sealed class CryptoAndFormatTests
{
    [TestMethod]
    public void EncryptDecryptRoundTripDefaultKdfPreservesEntriesAndHidesPlaintext()
    {
        byte[] masterBytes = TestHarness.CreateSampleMasterBytes();
        byte[] salt = RandomNumberGenerator.GetBytes(VaultHeader.SaltSize);
        byte[] dummyNonce = new byte[VaultHeader.NonceSize];

        (SecretBuffer key, byte[] verifier) =
            VaultKeyDerivation.DeriveKeyAndVerifier(masterBytes, salt, VaultKdfParameters.Default);
        using SecretBuffer entrySecret = SecretBuffer.CopyFrom(TestHarness.CreateSampleSecretBytes("github-demo"));
        using VaultEntry entry = new(1, "https://example.org", "alice.tester", entrySecret.Clone());
        using SecretBuffer ownedKey = key;

        VaultHeader template = new(
            VaultKdfParameters.Default.MemoryKiB,
            VaultKdfParameters.Default.Iterations,
            VaultKdfParameters.Default.Parallelism,
            salt,
            verifier,
            dummyNonce);

        using SecretBuffer serialized = VaultSerializer.Serialize([entry]);
        (byte[] vaultBytes, VaultHeader finalHeader) =
            VaultCrypto.Encrypt(template, "workshop", ownedKey, serialized.AsReadOnlySpan());

        Assert.IsTrue(VaultKeyDerivation.VerifyVerifier(finalHeader.Verifier, verifier));
        Assert.IsFalse(ContainsSubsequence(vaultBytes, masterBytes));
        Assert.IsFalse(ContainsSubsequence(vaultBytes, entrySecret.AsReadOnlySpan()));
        Assert.IsFalse(ContainsSubsequence(vaultBytes, Encoding.UTF8.GetBytes("https://example.org")));
        Assert.IsFalse(ContainsSubsequence(vaultBytes, Encoding.UTF8.GetBytes("alice.tester")));
        Assert.IsFalse(ContainsSubsequence(vaultBytes, Encoding.Unicode.GetBytes("sample-entry-secret-github-demo")));

        VaultHeader parsed = VaultHeader.Parse(vaultBytes);
        using SecretBuffer decrypted = VaultCrypto.Decrypt(vaultBytes, "workshop", ownedKey, parsed);
        List<VaultEntry> restored = VaultSerializer.Deserialize(decrypted.AsReadOnlySpan());
        try
        {
            Assert.HasCount(1, restored);
            Assert.AreEqual(1UL, restored[0].Id);
            Assert.AreEqual("https://example.org", restored[0].Site);
            Assert.AreEqual("alice.tester", restored[0].Username);
            Assert.IsTrue(restored[0].Password.AsReadOnlySpan().SequenceEqual(entrySecret.AsReadOnlySpan()));
        }
        finally
        {
            foreach (VaultEntry item in restored)
            {
                item.Dispose();
            }
        }
    }

    [TestMethod]
    public void DecryptRejectsBitFlipsInHeaderCiphertextAndTag()
    {
        byte[] masterBytes = TestHarness.CreateSampleMasterBytes();
        byte[] salt = RandomNumberGenerator.GetBytes(VaultHeader.SaltSize);
        (SecretBuffer key, byte[] verifier) =
            VaultKeyDerivation.DeriveKeyAndVerifier(masterBytes, salt, TestHarness.FastTestKdf);
        using SecretBuffer ownedKey = key;
        using VaultEntry entry = new(1, "site.test", "user.test", SecretBuffer.CopyFrom(TestHarness.CreateSampleSecretBytes("flip")));

        VaultHeader template = new(
            TestHarness.FastTestKdf.MemoryKiB,
            TestHarness.FastTestKdf.Iterations,
            TestHarness.FastTestKdf.Parallelism,
            salt,
            verifier,
            new byte[VaultHeader.NonceSize]);

        using SecretBuffer serialized = VaultSerializer.Serialize([entry]);
        (byte[] vaultBytes, VaultHeader header) =
            VaultCrypto.Encrypt(template, "myvault", ownedKey, serialized.AsReadOnlySpan());

        // Flip nonce byte in header (valid header structure, tampered AAD/nonce)
        byte[] tamperedHeader = (byte[])vaultBytes.Clone();
        tamperedHeader[70] ^= 0x01;
        VaultHeader parsedTamperedHeader = VaultHeader.Parse(tamperedHeader);
        Assert.ThrowsExactly<VaultCorruptedException>(() =>
        {
            using SecretBuffer _ = VaultCrypto.Decrypt(tamperedHeader, "myvault", ownedKey, parsedTamperedHeader);
        });

        // Flip ciphertext byte
        byte[] tamperedCipher = (byte[])vaultBytes.Clone();
        tamperedCipher[VaultHeader.HeaderSize + 1] ^= 0x80;
        Assert.ThrowsExactly<VaultCorruptedException>(() =>
        {
            using SecretBuffer _ = VaultCrypto.Decrypt(tamperedCipher, "myvault", ownedKey, header);
        });

        // Flip GCM tag byte
        byte[] tamperedTag = (byte[])vaultBytes.Clone();
        tamperedTag[^1] ^= 0x40;
        Assert.ThrowsExactly<VaultCorruptedException>(() =>
        {
            using SecretBuffer _ = VaultCrypto.Decrypt(tamperedTag, "myvault", ownedKey, header);
        });
    }

    [TestMethod]
    public void DecryptRejectsVaultNameMismatchDueToAadBinding()
    {
        byte[] masterBytes = TestHarness.CreateSampleMasterBytes();
        byte[] salt = RandomNumberGenerator.GetBytes(VaultHeader.SaltSize);
        (SecretBuffer key, byte[] verifier) =
            VaultKeyDerivation.DeriveKeyAndVerifier(masterBytes, salt, TestHarness.FastTestKdf);
        using SecretBuffer ownedKey = key;

        VaultHeader template = new(
            TestHarness.FastTestKdf.MemoryKiB,
            TestHarness.FastTestKdf.Iterations,
            TestHarness.FastTestKdf.Parallelism,
            salt,
            verifier,
            new byte[VaultHeader.NonceSize]);

        using SecretBuffer serialized = VaultSerializer.Serialize([]);
        (byte[] vaultBytes, VaultHeader header) =
            VaultCrypto.Encrypt(template, "alice", ownedKey, serialized.AsReadOnlySpan());

        Assert.ThrowsExactly<VaultCorruptedException>(() =>
        {
            using SecretBuffer _ = VaultCrypto.Decrypt(vaultBytes, "bob", ownedKey, header);
        });
    }

    [TestMethod]
    public void EncryptGeneratesFreshNoncePerSaveAndRejectsTruncatedVault()
    {
        byte[] masterBytes = TestHarness.CreateSampleMasterBytes();
        byte[] salt = RandomNumberGenerator.GetBytes(VaultHeader.SaltSize);
        (SecretBuffer key, byte[] verifier) =
            VaultKeyDerivation.DeriveKeyAndVerifier(masterBytes, salt, TestHarness.FastTestKdf);
        using SecretBuffer ownedKey = key;

        VaultHeader template = new(
            TestHarness.FastTestKdf.MemoryKiB,
            TestHarness.FastTestKdf.Iterations,
            TestHarness.FastTestKdf.Parallelism,
            salt,
            verifier,
            new byte[VaultHeader.NonceSize]);

        using SecretBuffer serialized = VaultSerializer.Serialize([]);
        (byte[] firstBytes, VaultHeader firstHeader) =
            VaultCrypto.Encrypt(template, "alice", ownedKey, serialized.AsReadOnlySpan());
        (byte[] _, VaultHeader secondHeader) =
            VaultCrypto.Encrypt(firstHeader, "alice", ownedKey, serialized.AsReadOnlySpan());

        Assert.IsFalse(firstHeader.Nonce.SequenceEqual(secondHeader.Nonce));

        byte[] truncated = firstBytes[..(VaultCrypto.MinVaultBytes - 1)];
        Assert.ThrowsExactly<VaultCorruptedException>(() =>
        {
            using SecretBuffer _ = VaultCrypto.Decrypt(truncated, "alice", ownedKey, firstHeader);
        });
    }

    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        return !needle.IsEmpty && haystack.IndexOf(needle) >= 0;
    }
}
