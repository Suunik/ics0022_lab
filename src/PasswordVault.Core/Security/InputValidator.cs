using System.Text;
using System.Text.Unicode;
using PasswordVault.Core.Models;

namespace PasswordVault.Core.Security;

/// <summary>
/// Centralizes strict boundary, encoding, and character validation for vault inputs and deserialized data.
/// </summary>
public static class InputValidator
{
    public const int MinVaultNameLength = 3;
    public const int MaxVaultNameLength = 32;

    public const int MinMasterPassphraseBytes = 16;
    public const int MaxMasterPassphraseBytes = 128;

    public const int MinTextFieldBytes = 1;
    public const int MaxTextFieldBytes = 1024;

    public const int MinEntryPasswordBytes = 1;
    public const int MaxEntryPasswordBytes = 4094;

    private static readonly HashSet<string> ReservedWindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /// <summary>
    /// Validates a vault name against safe filename and traversal rules.
    /// </summary>
    public static string ValidateVaultName(string? vaultName)
    {
        if (string.IsNullOrEmpty(vaultName) ||
            vaultName.Length < MinVaultNameLength ||
            vaultName.Length > MaxVaultNameLength)
        {
            throw new VaultValidationException(
                $"Vault name must be {MinVaultNameLength}-{MaxVaultNameLength} characters.");
        }

        foreach (char c in vaultName)
        {
            bool allowed = (c >= 'A' && c <= 'Z') ||
                           (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') ||
                           c == '_' ||
                           c == '-';
            if (!allowed)
            {
                throw new VaultValidationException(
                    "Vault name may only contain ASCII letters, digits, '_' and '-'.");
            }
        }

        if (ReservedWindowsNames.Contains(vaultName))
        {
            throw new VaultValidationException("Vault name cannot be a reserved device name.");
        }

        return vaultName;
    }

    /// <summary>
    /// Validates a master passphrase when creating a new vault.
    /// </summary>
    public static void ValidateNewMasterPassphrase(ReadOnlySpan<byte> utf8Bytes)
    {
        if (utf8Bytes.Length < MinMasterPassphraseBytes || utf8Bytes.Length > MaxMasterPassphraseBytes)
        {
            throw new VaultValidationException(
                $"Master passphrase must be {MinMasterPassphraseBytes}-{MaxMasterPassphraseBytes} UTF-8 bytes.");
        }

        ValidatePassphraseCharacters(utf8Bytes, "Master passphrase");
    }

    /// <summary>
    /// Validates the structural bounds of an unlock passphrase attempt without leaking policy minimums.
    /// </summary>
    public static void ValidateUnlockMasterPassphrase(ReadOnlySpan<byte> utf8Bytes)
    {
        if (utf8Bytes.IsEmpty || utf8Bytes.Length > MaxMasterPassphraseBytes)
        {
            throw new VaultValidationException(
                $"Master passphrase must be 1-{MaxMasterPassphraseBytes} UTF-8 bytes.");
        }

        ValidatePassphraseCharacters(utf8Bytes, "Master passphrase");
    }

    /// <summary>
    /// Validates a credential website or service name.
    /// </summary>
    public static string ValidateSite(string? site)
    {
        return ValidateTextField(site, "Website");
    }

    /// <summary>
    /// Validates a credential username.
    /// </summary>
    public static string ValidateUsername(string? username)
    {
        return ValidateTextField(username, "Username");
    }

    /// <summary>
    /// Validates raw UTF-8 bytes for a website field during binary deserialization.
    /// </summary>
    public static string ValidateSiteBytes(ReadOnlySpan<byte> utf8Bytes)
    {
        return ValidateTextFieldBytes(utf8Bytes, "Website");
    }

    /// <summary>
    /// Validates raw UTF-8 bytes for a username field during binary deserialization.
    /// </summary>
    public static string ValidateUsernameBytes(ReadOnlySpan<byte> utf8Bytes)
    {
        return ValidateTextFieldBytes(utf8Bytes, "Username");
    }

    /// <summary>
    /// Validates an entry password's UTF-8 byte length, encoding, and forbidden control characters.
    /// </summary>
    public static void ValidateEntryPassword(ReadOnlySpan<byte> utf8Bytes)
    {
        if (utf8Bytes.Length < MinEntryPasswordBytes || utf8Bytes.Length > MaxEntryPasswordBytes)
        {
            throw new VaultValidationException(
                $"Password must be {MinEntryPasswordBytes}-{MaxEntryPasswordBytes} UTF-8 bytes.");
        }

        ValidatePassphraseCharacters(utf8Bytes, "Password");
    }

    private static string ValidateTextField(string? value, string fieldName)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new VaultValidationException($"{fieldName} is required.");
        }

        int byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount < MinTextFieldBytes || byteCount > MaxTextFieldBytes)
        {
            throw new VaultValidationException(
                $"{fieldName} must be {MinTextFieldBytes}-{MaxTextFieldBytes} UTF-8 bytes.");
        }

        EnsureNoControlCharacters(value, fieldName);
        return value;
    }

    private static string ValidateTextFieldBytes(ReadOnlySpan<byte> utf8Bytes, string fieldName)
    {
        if (utf8Bytes.Length < MinTextFieldBytes || utf8Bytes.Length > MaxTextFieldBytes)
        {
            throw new VaultCorruptedException($"{fieldName} length in vault is invalid.");
        }

        if (!Utf8.IsValid(utf8Bytes))
        {
            throw new VaultCorruptedException($"{fieldName} in vault is not valid UTF-8.");
        }

        string decoded = Encoding.UTF8.GetString(utf8Bytes);
        foreach (Rune rune in decoded.EnumerateRunes())
        {
            if (IsControlCharacter(rune.Value))
            {
                throw new VaultCorruptedException($"{fieldName} in vault contains disallowed control characters.");
            }
        }

        return decoded;
    }

    private static void EnsureNoControlCharacters(string value, string fieldName)
    {
        foreach (Rune rune in value.EnumerateRunes())
        {
            if (IsControlCharacter(rune.Value))
            {
                throw new VaultValidationException($"{fieldName} cannot contain control characters.");
            }
        }
    }

    private static bool IsControlCharacter(int codePoint)
    {
        return codePoint < 0x20 || codePoint == 0x7F || (codePoint >= 0x80 && codePoint <= 0x9F);
    }

    private static void ValidatePassphraseCharacters(ReadOnlySpan<byte> utf8Bytes, string fieldName)
    {
        if (!Utf8.IsValid(utf8Bytes))
        {
            throw new VaultValidationException($"{fieldName} must be valid UTF-8.");
        }

        foreach (byte b in utf8Bytes)
        {
            if (b is 0x00 or 0x0A or 0x0D)
            {
                throw new VaultValidationException($"{fieldName} cannot contain NUL or newline characters.");
            }
        }
    }
}
