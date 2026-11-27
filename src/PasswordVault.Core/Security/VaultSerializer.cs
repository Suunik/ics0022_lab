using System.Buffers.Binary;
using System.Text;
using PasswordVault.Core.Models;

namespace PasswordVault.Core.Security;

/// <summary>
/// Serializes and deserializes vault credential records into a bounded little-endian binary layout.
/// </summary>
public static class VaultSerializer
{
    public const int MaxPlaintextBytes = 65536;
    private const int RecordHeaderBytes = 8 + 4 + 4 + 4;

    /// <summary>
    /// Serializes all entries into a zeroizable <see cref="SecretBuffer"/>, enforcing the 64 KiB payload ceiling.
    /// </summary>
    public static SecretBuffer Serialize(IReadOnlyList<VaultEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        long totalBytes = 4;
        foreach (VaultEntry entry in entries)
        {
            int siteBytes = Encoding.UTF8.GetByteCount(entry.Site);
            int userBytes = Encoding.UTF8.GetByteCount(entry.Username);
            int passBytes = entry.Password.Length;

            totalBytes += RecordHeaderBytes + (long)siteBytes + userBytes + passBytes;
            if (totalBytes > MaxPlaintextBytes)
            {
                throw new VaultCapacityException(
                    $"Vault payload exceeds the {MaxPlaintextBytes}-byte capacity limit.");
            }
        }

        SecretBuffer output = SecretBuffer.Allocate((int)totalBytes);
        try
        {
            Span<byte> span = output.AsSpan();
            int offset = 0;

            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)entries.Count);
            offset += 4;

            foreach (VaultEntry entry in entries)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(offset, 8), entry.Id);
                offset += 8;

                offset = WriteLengthPrefixedUtf8(span, offset, entry.Site);
                offset = WriteLengthPrefixedUtf8(span, offset, entry.Username);
                offset = WriteLengthPrefixedBytes(span, offset, entry.Password.AsReadOnlySpan());
            }

            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Deserializes and validates credential records from decrypted vault plaintext bytes.
    /// </summary>
    public static List<VaultEntry> Deserialize(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length < 4 || plaintext.Length > MaxPlaintextBytes)
        {
            throw new VaultCorruptedException("Vault plaintext payload size is invalid.");
        }

        uint recordCount = BinaryPrimitives.ReadUInt32LittleEndian(plaintext[..4]);
        int offset = 4;

        if (recordCount > (uint)((plaintext.Length - offset) / RecordHeaderBytes))
        {
            throw new VaultCorruptedException("Vault record count exceeds available payload bytes.");
        }

        var entries = new List<VaultEntry>((int)recordCount);
        var seenIds = new HashSet<ulong>();

        try
        {
            for (uint i = 0; i < recordCount; i++)
            {
                if (plaintext.Length - offset < sizeof(ulong))
                {
                    throw new VaultCorruptedException("Unexpected end of vault record header.");
                }

                ulong id = BinaryPrimitives.ReadUInt64LittleEndian(plaintext.Slice(offset, 8));
                offset += 8;

                if (id == 0 || !seenIds.Add(id))
                {
                    throw new VaultCorruptedException("Vault contains an invalid or duplicate entry identifier.");
                }

                ReadOnlySpan<byte> siteBytes = ReadLengthPrefixedSlice(plaintext, ref offset);
                string site = InputValidator.ValidateSiteBytes(siteBytes);

                ReadOnlySpan<byte> userBytes = ReadLengthPrefixedSlice(plaintext, ref offset);
                string username = InputValidator.ValidateUsernameBytes(userBytes);

                ReadOnlySpan<byte> passBytes = ReadLengthPrefixedSlice(plaintext, ref offset);
                SecretBuffer password = ValidateAndCopyPassword(passBytes);

                try
                {
                    entries.Add(new VaultEntry(id, site, username, password));
                }
                catch
                {
                    password.Dispose();
                    throw;
                }
            }

            if (offset != plaintext.Length)
            {
                throw new VaultCorruptedException("Vault plaintext contains unexpected trailing bytes.");
            }

            return entries;
        }
        catch
        {
            foreach (VaultEntry entry in entries)
            {
                entry.Dispose();
            }

            throw;
        }
    }

    private static int WriteLengthPrefixedUtf8(Span<byte> destination, int offset, string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset, 4), (uint)byteCount);
        offset += 4;
        int written = Encoding.UTF8.GetBytes(value, destination.Slice(offset, byteCount));
        return offset + written;
    }

    private static int WriteLengthPrefixedBytes(Span<byte> destination, int offset, ReadOnlySpan<byte> bytes)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset, 4), (uint)bytes.Length);
        offset += 4;
        bytes.CopyTo(destination.Slice(offset, bytes.Length));
        return offset + bytes.Length;
    }

    private static ReadOnlySpan<byte> ReadLengthPrefixedSlice(ReadOnlySpan<byte> source, ref int offset)
    {
        if (source.Length - offset < 4)
        {
            throw new VaultCorruptedException("Unexpected end of vault field length.");
        }

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(offset, 4));
        offset += 4;

        if (length > (uint)(source.Length - offset))
        {
            throw new VaultCorruptedException("Vault field length exceeds payload bounds.");
        }

        ReadOnlySpan<byte> slice = source.Slice(offset, (int)length);
        offset += (int)length;
        return slice;
    }

    private static SecretBuffer ValidateAndCopyPassword(ReadOnlySpan<byte> passwordBytes)
    {
        try
        {
            InputValidator.ValidateEntryPassword(passwordBytes);
        }
        catch (VaultValidationException ex)
        {
            throw new VaultCorruptedException("Stored entry password failed integrity validation.", ex);
        }

        return SecretBuffer.CopyFrom(passwordBytes);
    }
}
