using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Core.Security;

/// <summary>
/// Holds sensitive byte material and zeroes it deterministically on disposal.
/// </summary>
public sealed class SecretBuffer : IDisposable
{
    private readonly byte[] _buffer;
    private bool _disposed;

    private SecretBuffer(byte[] buffer)
    {
        _buffer = buffer;
    }

    /// <summary>
    /// Allocates a new zero-initialized secret buffer of the requested length.
    /// </summary>
    public static SecretBuffer Allocate(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        return new SecretBuffer(new byte[length]);
    }

    /// <summary>
    /// Creates a new secret buffer initialized with a copy of <paramref name="source"/>.
    /// </summary>
    public static SecretBuffer CopyFrom(ReadOnlySpan<byte> source)
    {
        byte[] copy = new byte[source.Length];
        source.CopyTo(copy);
        return new SecretBuffer(copy);
    }

    /// <summary>
    /// Gets the length in bytes of the protected buffer.
    /// </summary>
    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _buffer.Length;
        }
    }

    /// <summary>
    /// Returns a writable span over the underlying secret bytes.
    /// </summary>
    public Span<byte> AsSpan()
    {
        ThrowIfDisposed();
        return _buffer.AsSpan();
    }

    /// <summary>
    /// Returns a read-only span over the underlying secret bytes.
    /// </summary>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ThrowIfDisposed();
        return _buffer.AsSpan();
    }

    /// <summary>
    /// Creates an independent copy of this secret buffer.
    /// </summary>
    public SecretBuffer Clone()
    {
        ThrowIfDisposed();
        return CopyFrom(_buffer);
    }

    /// <summary>
    /// Decodes the protected UTF-8 bytes into a managed string only at explicit UI display boundaries.
    /// </summary>
    public string ToUtf8String()
    {
        ThrowIfDisposed();
        return Encoding.UTF8.GetString(_buffer);
    }

    /// <inheritdoc />
    public override string ToString() => "[REDACTED]";

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_buffer);
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
