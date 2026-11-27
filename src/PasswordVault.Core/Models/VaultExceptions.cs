namespace PasswordVault.Core.Models;

/// <summary>
/// Base exception for all domain errors raised by the password vault.
/// </summary>
public class VaultException : Exception
{
    public VaultException()
    {
    }

    public VaultException(string message)
        : base(message)
    {
    }

    public VaultException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when vault authentication fails (for example, an incorrect master passphrase).
/// </summary>
public sealed class VaultAuthenticationException : VaultException
{
    public VaultAuthenticationException()
    {
    }

    public VaultAuthenticationException(string message)
        : base(message)
    {
    }

    public VaultAuthenticationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when vault data fails structural or authenticated integrity verification.
/// </summary>
public sealed class VaultCorruptedException : VaultException
{
    public VaultCorruptedException()
    {
    }

    public VaultCorruptedException(string message)
        : base(message)
    {
    }

    public VaultCorruptedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when caller input violates vault validation constraints.
/// </summary>
public sealed class VaultValidationException : VaultException
{
    public VaultValidationException()
    {
    }

    public VaultValidationException(string message)
        : base(message)
    {
    }

    public VaultValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when an operation requiring an unlocked session is attempted while locked or unauthorized.
/// </summary>
public sealed class VaultLockedException : VaultException
{
    public VaultLockedException()
    {
    }

    public VaultLockedException(string message)
        : base(message)
    {
    }

    public VaultLockedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when hardened storage or audit log checks fail.
/// </summary>
public sealed class VaultStorageException : VaultException
{
    public VaultStorageException()
    {
    }

    public VaultStorageException(string message)
        : base(message)
    {
    }

    public VaultStorageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when adding or updating an entry would exceed the vault plaintext capacity limit.
/// </summary>
public sealed class VaultCapacityException : VaultException
{
    public VaultCapacityException()
    {
    }

    public VaultCapacityException(string message)
        : base(message)
    {
    }

    public VaultCapacityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
