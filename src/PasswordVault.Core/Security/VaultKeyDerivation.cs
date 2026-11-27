using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using PasswordVault.Core.Models;

namespace PasswordVault.Core.Security;

/// <summary>
/// Derives the AES-256 encryption key and SHA-256 key verifier from a master passphrase using Argon2id.
/// </summary>
public static class VaultKeyDerivation
{
    public const int EncryptionKeySize = 32;
    private const int DerivedKeyBytes = 64;

    /// <summary>
    /// Derives a 32-byte encryption key inside a <see cref="SecretBuffer"/> and a 32-byte verifier hash.
    /// </summary>
    public static (SecretBuffer EncryptionKey, byte[] Verifier) DeriveKeyAndVerifier(
        ReadOnlySpan<byte> masterPassphraseUtf8,
        ReadOnlySpan<byte> salt,
        VaultKdfParameters kdfParameters)
    {
        ArgumentNullException.ThrowIfNull(kdfParameters);

        if (salt.Length != VaultHeader.SaltSize)
        {
            throw new ArgumentException($"Salt must be {VaultHeader.SaltSize} bytes.", nameof(salt));
        }

        byte[] passwordCopy = masterPassphraseUtf8.ToArray();
        byte[] derived = new byte[DerivedKeyBytes];

        try
        {
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithSalt(salt.ToArray())
                .WithMemoryAsKB((int)kdfParameters.MemoryKiB)
                .WithIterations((int)kdfParameters.Iterations)
                .WithParallelism((int)kdfParameters.Parallelism)
                .Build();

            Argon2BytesGenerator generator = new();
            generator.Init(parameters);
            generator.GenerateBytes(passwordCopy, derived);

            SecretBuffer encryptionKey = SecretBuffer.CopyFrom(derived.AsSpan(0, EncryptionKeySize));
            byte[] verifier = SHA256.HashData(derived.AsSpan(EncryptionKeySize, VaultHeader.VerifierSize));
            return (encryptionKey, verifier);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(passwordCopy);
        }
    }

    /// <summary>
    /// Performs a constant-time comparison between expected and computed key verifiers.
    /// </summary>
    public static bool VerifyVerifier(ReadOnlySpan<byte> expectedVerifier, ReadOnlySpan<byte> actualVerifier)
    {
        return expectedVerifier.Length == VaultHeader.VerifierSize &&
               actualVerifier.Length == VaultHeader.VerifierSize &&
               CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier);
    }
}
