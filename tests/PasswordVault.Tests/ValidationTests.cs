using System.Buffers.Binary;
using System.Text;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;

namespace PasswordVault.Tests;

[TestClass]
public sealed class ValidationTests
{
    [TestMethod]
    public void ValidateVaultNameRejectsTraversalReservedAndInvalidCharacters()
    {
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName(null));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName("ab"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName(new string('a', 33)));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName("../evil"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName("a/b"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName("a\\b"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName("CON"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateVaultName("nul"));

        Assert.AreEqual("vault_01-main", InputValidator.ValidateVaultName("vault_01-main"));
    }

    [TestMethod]
    public void ValidateMasterPassphraseEnforcesLengthUtf8AndControlByteRules()
    {
        Assert.ThrowsExactly<VaultValidationException>(
            () => InputValidator.ValidateNewMasterPassphrase("short-15-bytes!"u8));
        Assert.ThrowsExactly<VaultValidationException>(
            () => InputValidator.ValidateNewMasterPassphrase(new byte[129]));

        byte[] withNul = Encoding.UTF8.GetBytes("valid-sixteen-byte\0pass");
        Assert.ThrowsExactly<VaultValidationException>(
            () => InputValidator.ValidateNewMasterPassphrase(withNul));

        byte[] withNewline = Encoding.UTF8.GetBytes("valid-sixteen-byte\npass");
        Assert.ThrowsExactly<VaultValidationException>(
            () => InputValidator.ValidateNewMasterPassphrase(withNewline));

        byte[] invalidUtf8 = [0xFF, 0xFE, .. Encoding.UTF8.GetBytes("sixteen-byte-padding")];
        Assert.ThrowsExactly<VaultValidationException>(
            () => InputValidator.ValidateNewMasterPassphrase(invalidUtf8));

        InputValidator.ValidateNewMasterPassphrase("exactly-16-bytes"u8);
    }

    [TestMethod]
    public void ValidateSiteUsernameAndEntryPasswordEnforceBoundsAndControlChars()
    {
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateSite(string.Empty));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateSite(new string('s', 1025)));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateSite("bad\tsite"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateUsername("bad\u007Fuser"));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateUsername("bad\u0085user"));

        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateEntryPassword([]));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateEntryPassword(new byte[4095]));
        Assert.ThrowsExactly<VaultValidationException>(() => InputValidator.ValidateEntryPassword("pw\r123"u8));

        Assert.AreEqual("github.com", InputValidator.ValidateSite("github.com"));
        Assert.AreEqual("user@example.com", InputValidator.ValidateUsername("user@example.com"));
        InputValidator.ValidateEntryPassword("valid-secret"u8);
    }

    [TestMethod]
    public void SerializerRejectsTrailingBytesZeroIdDuplicateIdsAndCorruptedLengths()
    {
        using VaultEntry valid = new(1, "site", "user", SecretBuffer.CopyFrom(TestHarness.CreateSampleSecretBytes("s1")));
        using SecretBuffer serialized = VaultSerializer.Serialize([valid]);

        // Trailing garbage byte
        byte[] withTrailing = [.. serialized.AsReadOnlySpan(), 0x00];
        Assert.ThrowsExactly<VaultCorruptedException>(() => VaultSerializer.Deserialize(withTrailing));

        // Zero ID
        byte[] zeroId = serialized.AsReadOnlySpan().ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(zeroId.AsSpan(4, 8), 0);
        Assert.ThrowsExactly<VaultCorruptedException>(() => VaultSerializer.Deserialize(zeroId));

        // Duplicate IDs
        using VaultEntry duplicate = new(1, "site2", "user2", SecretBuffer.CopyFrom(TestHarness.CreateSampleSecretBytes("s2")));
        using SecretBuffer dupBytes = VaultSerializer.Serialize([valid, duplicate]);
        Assert.ThrowsExactly<VaultCorruptedException>(() => VaultSerializer.Deserialize(dupBytes.AsReadOnlySpan()));

        // Corrupted string length
        byte[] badLength = serialized.AsReadOnlySpan().ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(badLength.AsSpan(12, 4), 9999);
        Assert.ThrowsExactly<VaultCorruptedException>(() => VaultSerializer.Deserialize(badLength));
    }
}
