namespace PasswordVault.Core.Storage;

/// <summary>
/// Enumerated vault lifecycle and access events recorded in the secret-free audit log.
/// </summary>
public enum AuditEvent
{
    Create,
    Unlock,
    Lock,
    AddEntry,
    UpdateEntry,
    DeleteEntry,
    RevealPassword,
    AccessDenied
}

/// <summary>
/// Outcome classification for an audit event.
/// </summary>
public enum AuditOutcome
{
    Success,
    Failure,
    Denied
}
