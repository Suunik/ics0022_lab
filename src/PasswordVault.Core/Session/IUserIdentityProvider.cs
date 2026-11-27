namespace PasswordVault.Core.Session;

/// <summary>
/// Resolves the current OS user identifier for session binding and audit logging.
/// </summary>
public interface IUserIdentityProvider
{
    string GetCurrentUserIdentifier();
}
