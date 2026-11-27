using System.Buffers.Binary;

namespace PasswordVault.Core.Models;

/// <summary>
/// Fixed 80-byte authenticated public header for the encrypted vault format.
/// </summary>
public sealed class VaultHeader
{
    public const int HeaderSize = 80;
    public const uint CurrentVersion = 1;
    public const int SaltSize = 16;
    public const int VerifierSize = 32;
    public const int NonceSize = 12;

    public const uint MinMemoryKiB = 19456;
    public const uint MaxMemoryKiB = 262144;
    public const uint MinIterations = 2;
    public const uint MaxIterations = 20;
    public const uint MinParallelism = 1;
    public const uint MaxParallelism = 8;

    private static readonly byte[] MagicBytes = "PWMV"u8.ToArray();

    private readonly byte[] _salt;
    private readonly byte[] _verifier;
    private readonly byte[] _nonce;

    public VaultHeader(
        uint memoryKiB,
        uint iterations,
        uint parallelism,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> verifier,
        ReadOnlySpan<byte> nonce)
    {
        ValidateKdfParameters(memoryKiB, iterations, parallelism);
        ValidateBufferLength(salt, SaltSize, nameof(salt));
        ValidateBufferLength(verifier, VerifierSize, nameof(verifier));
        ValidateBufferLength(nonce, NonceSize, nameof(nonce));

        Version = CurrentVersion;
        MemoryKiB = memoryKiB;
        Iterations = iterations;
        Parallelism = parallelism;
        _salt = salt.ToArray();
        _verifier = verifier.ToArray();
        _nonce = nonce.ToArray();
    }

    public uint Version { get; }

    public uint MemoryKiB { get; }

    public uint Iterations { get; }

    public uint Parallelism { get; }

    public ReadOnlySpan<byte> Salt => _salt;

    public ReadOnlySpan<byte> Verifier => _verifier;

    public ReadOnlySpan<byte> Nonce => _nonce;

    /// <summary>
    /// Validates Argon2id parameters against OWASP minimum and safe resource ceiling bounds.
    /// </summary>
    public static void ValidateKdfParameters(uint memoryKiB, uint iterations, uint parallelism)
    {
        if (memoryKiB is < MinMemoryKiB or > MaxMemoryKiB)
        {
            throw new VaultCorruptedException("Vault KDF memory parameter is outside allowed bounds.");
        }

        if (iterations is < MinIterations or > MaxIterations)
        {
            throw new VaultCorruptedException("Vault KDF iteration count is outside allowed bounds.");
        }

        if (parallelism is < MinParallelism or > MaxParallelism)
        {
            throw new VaultCorruptedException("Vault KDF parallelism is outside allowed bounds.");
        }
    }

    /// <summary>
    /// Parses and validates an 80-byte vault header from a byte span.
    /// </summary>
    public static VaultHeader Parse(ReadOnlySpan<byte> source)
    {
        if (source.Length < HeaderSize)
        {
            throw new VaultCorruptedException("Vault header is truncated.");
        }

        if (!source[..MagicBytes.Length].SequenceEqual(MagicBytes))
        {
            throw new VaultCorruptedException("Vault magic header is invalid.");
        }

        uint version = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(4, 4));
        if (version != CurrentVersion)
        {
            throw new VaultCorruptedException("Vault version is unsupported.");
        }

        uint memoryKiB = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(8, 4));
        uint iterations = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(12, 4));
        uint parallelism = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(16, 4));
        ValidateKdfParameters(memoryKiB, iterations, parallelism);

        ReadOnlySpan<byte> salt = source.Slice(20, SaltSize);
        ReadOnlySpan<byte> verifier = source.Slice(36, VerifierSize);
        ReadOnlySpan<byte> nonce = source.Slice(68, NonceSize);

        return new VaultHeader(memoryKiB, iterations, parallelism, salt, verifier, nonce);
    }

    /// <summary>
    /// Returns a copy of this header with a freshly generated 12-byte GCM nonce.
    /// </summary>
    public VaultHeader WithNewNonce(ReadOnlySpan<byte> newNonce)
    {
        return new VaultHeader(MemoryKiB, Iterations, Parallelism, _salt, _verifier, newNonce);
    }

    /// <summary>
    /// Writes the 80-byte binary representation of the header into <paramref name="destination"/>.
    /// </summary>
    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < HeaderSize)
        {
            throw new ArgumentException("Destination buffer is smaller than the vault header size.", nameof(destination));
        }

        MagicBytes.CopyTo(destination);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(4, 4), Version);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(8, 4), MemoryKiB);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12, 4), Iterations);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(16, 4), Parallelism);
        _salt.CopyTo(destination.Slice(20, SaltSize));
        _verifier.CopyTo(destination.Slice(36, VerifierSize));
        _nonce.CopyTo(destination.Slice(68, NonceSize));
    }

    /// <summary>
    /// Serializes this header to a new 80-byte array.
    /// </summary>
    public byte[] ToArray()
    {
        byte[] buffer = new byte[HeaderSize];
        WriteTo(buffer);
        return buffer;
    }

    private static void ValidateBufferLength(ReadOnlySpan<byte> buffer, int expectedLength, string paramName)
    {
        if (buffer.Length != expectedLength)
        {
            throw new ArgumentException($"Expected exactly {expectedLength} bytes.", paramName);
        }
    }
}
