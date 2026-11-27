using System.Security.Cryptography;
using System.Text;
using PasswordVault.Core.Models;

namespace PasswordVault.Core.Security;

/// <summary>
/// Provides authenticated AES-256-GCM encryption and decryption binding the header and vault name as AAD.
/// </summary>
public static class VaultCrypto
{
    public const int TagSize = 16;
    public const int MinVaultBytes = VaultHeader.HeaderSize + 4 + TagSize;
    public const int MaxVaultBytes = VaultHeader.HeaderSize + VaultSerializer.MaxPlaintextBytes + TagSize;

    /// <summary>
    /// Encrypts serialized vault plaintext with a fresh random 96-bit nonce and returns the complete vault bytes.
    /// </summary>
    public static (byte[] VaultBytes, VaultHeader UpdatedHeader) Encrypt(
        VaultHeader headerTemplate,
        string vaultName,
        SecretBuffer encryptionKey,
        ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(headerTemplate);
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ValidateEncryptionKey(encryptionKey);

        if (plaintext.Length < 4 || plaintext.Length > VaultSerializer.MaxPlaintextBytes)
        {
            throw new VaultCapacityException("Vault plaintext payload size is outside allowed bounds.");
        }

        Span<byte> nonce = stackalloc byte[VaultHeader.NonceSize];
        RandomNumberGenerator.Fill(nonce);

        VaultHeader updatedHeader = headerTemplate.WithNewNonce(nonce);
        byte[] output = new byte[VaultHeader.HeaderSize + plaintext.Length + TagSize];
        Span<byte> headerSpan = output.AsSpan(0, VaultHeader.HeaderSize);
        updatedHeader.WriteTo(headerSpan);

        byte[] aad = BuildAad(headerSpan, vaultName);
        Span<byte> ciphertext = output.AsSpan(VaultHeader.HeaderSize, plaintext.Length);
        Span<byte> tag = output.AsSpan(VaultHeader.HeaderSize + plaintext.Length, TagSize);

        using AesGcm aes = new(encryptionKey.AsReadOnlySpan(), TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return (output, updatedHeader);
    }

    /// <summary>
    /// Decrypts vault bytes and verifies header + vault-name AAD and the 16-byte authentication tag.
    /// </summary>
    public static SecretBuffer Decrypt(
        ReadOnlySpan<byte> vaultBytes,
        string vaultName,
        SecretBuffer encryptionKey,
        VaultHeader expectedHeader)
    {
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(expectedHeader);
        ValidateEncryptionKey(encryptionKey);

        if (vaultBytes.Length < MinVaultBytes || vaultBytes.Length > MaxVaultBytes)
        {
            throw new VaultCorruptedException("Vault file size is outside valid bounds.");
        }

        ReadOnlySpan<byte> headerSpan = vaultBytes[..VaultHeader.HeaderSize];
        int cipherLength = vaultBytes.Length - VaultHeader.HeaderSize - TagSize;
        ReadOnlySpan<byte> ciphertext = vaultBytes.Slice(VaultHeader.HeaderSize, cipherLength);
        ReadOnlySpan<byte> tag = vaultBytes.Slice(VaultHeader.HeaderSize + cipherLength, TagSize);

        byte[] aad = BuildAad(headerSpan, vaultName);
        SecretBuffer plaintext = SecretBuffer.Allocate(cipherLength);

        try
        {
            using AesGcm aes = new(encryptionKey.AsReadOnlySpan(), TagSize);
            aes.Decrypt(expectedHeader.Nonce, ciphertext, tag, plaintext.AsSpan(), aad);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            plaintext.Dispose();
            throw new VaultCorruptedException("Vault authentication tag verification failed.", ex);
        }
        catch
        {
            plaintext.Dispose();
            throw;
        }
    }

    private static byte[] BuildAad(ReadOnlySpan<byte> headerBytes, string vaultName)
    {
        string validatedName = InputValidator.ValidateVaultName(vaultName);
        int nameByteCount = Encoding.UTF8.GetByteCount(validatedName);
        byte[] aad = new byte[VaultHeader.HeaderSize + nameByteCount];
        headerBytes.CopyTo(aad);
        Encoding.UTF8.GetBytes(validatedName, aad.AsSpan(VaultHeader.HeaderSize, nameByteCount));
        return aad;
    }

    private static void ValidateEncryptionKey(SecretBuffer encryptionKey)
    {
        if (encryptionKey.Length != VaultKeyDerivation.EncryptionKeySize)
        {
            throw new ArgumentException(
                $"Encryption key must be {VaultKeyDerivation.EncryptionKeySize} bytes.",
                nameof(encryptionKey));
        }
    }
}
