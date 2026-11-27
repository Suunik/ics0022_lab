using System.Globalization;
using System.Text;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;
using PasswordVault.Core.Session;

namespace PasswordVault.Core.Storage;

/// <summary>
/// Appends secret-free audit entries to <c>pwm.log</c> while enforcing owner-only ACLs and symlink checks.
/// </summary>
public sealed class FileAuditLog : IAuditLog
{
    public const string LogFileName = "pwm.log";

    private readonly string _baseDirectory;
    private readonly string _logPath;
    private readonly IUserIdentityProvider _identityProvider;
    private readonly Lock _syncLock = new();

    public FileAuditLog(string? baseDirectory = null, IUserIdentityProvider? identityProvider = null)
    {
        _baseDirectory = Path.GetFullPath(baseDirectory ?? FileVaultStorage.GetDefaultVaultDirectory());
        _logPath = Path.Combine(_baseDirectory, LogFileName);
        _identityProvider = identityProvider ?? new WindowsUserIdentityProvider();
    }

    public string LogPath => _logPath;

    /// <inheritdoc />
    public void Record(string vaultName, AuditEvent auditEvent, AuditOutcome outcome, ulong? recordId = null)
    {
        string safeVaultName = SanitizeVaultName(vaultName);
        string recordIdText = recordId.HasValue
            ? recordId.Value.ToString(CultureInfo.InvariantCulture)
            : "-";
        string userSid = _identityProvider.GetCurrentUserIdentifier();

        string line = string.Format(
            CultureInfo.InvariantCulture,
            "ts={0:O} pid={1} user={2} vault={3} event={4} record_id={5} outcome={6}{7}",
            DateTimeOffset.UtcNow,
            Environment.ProcessId,
            userSid,
            safeVaultName,
            auditEvent,
            recordIdText,
            outcome,
            Environment.NewLine);

        byte[] lineBytes = Encoding.UTF8.GetBytes(line);

        lock (_syncLock)
        {
            WindowsAclHelper.EnsureDirectorySecure(_baseDirectory);

            bool existed = File.Exists(_logPath);
            if (existed)
            {
                WindowsAclHelper.VerifyFileAcl(_logPath);
            }

            using FileStream stream = new(_logPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
            if (!existed)
            {
                WindowsAclHelper.ApplyOwnerOnlyFileAcl(_logPath);
            }

            stream.Seek(0, SeekOrigin.End);
            stream.Write(lineBytes, 0, lineBytes.Length);
            stream.Flush(flushToDisk: true);
        }
    }

    private static string SanitizeVaultName(string vaultName)
    {
        try
        {
            return InputValidator.ValidateVaultName(vaultName);
        }
        catch (VaultValidationException)
        {
            return "<invalid>";
        }
    }
}
