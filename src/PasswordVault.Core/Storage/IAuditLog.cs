namespace PasswordVault.Core.Storage;

/// <summary>
/// Records structured security audit events without accepting secret fields.
/// </summary>
public interface IAuditLog
{
    void Record(string vaultName, AuditEvent auditEvent, AuditOutcome outcome, ulong? recordId = null);
}
