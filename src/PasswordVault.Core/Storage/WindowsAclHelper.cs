using System.Security.AccessControl;
using System.Security.Principal;
using PasswordVault.Core.Models;

namespace PasswordVault.Core.Storage;

/// <summary>
/// Enforces Windows owner-only ACLs and rejects reparse points (symlinks/junctions) for vault files and directories.
/// </summary>
internal static class WindowsAclHelper
{
    internal static SecurityIdentifier GetCurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User ?? throw new VaultStorageException("Unable to resolve current Windows user SID.");
    }

    internal static void EnsureDirectorySecure(string directoryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);

        if (!Directory.Exists(directoryPath))
        {
            DirectoryInfo created = Directory.CreateDirectory(directoryPath);
            created.SetAccessControl(CreateOwnerOnlyDirectorySecurity());
        }

        EnsureNotReparsePoint(directoryPath);
        VerifyDirectoryAcl(directoryPath);
    }

    internal static void EnsureNotReparsePoint(string path)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new VaultStorageException("Symbolic links, junctions, and reparse points are not permitted.");
        }
    }

    internal static void ApplyOwnerOnlyFileAcl(string filePath)
    {
        FileInfo fileInfo = new(filePath);
        fileInfo.SetAccessControl(CreateOwnerOnlyFileSecurity());
    }

    internal static void VerifyFileAcl(string filePath)
    {
        EnsureNotReparsePoint(filePath);
        FileInfo fileInfo = new(filePath);
        FileSecurity security = fileInfo.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        VerifySecurityDescriptor(security, "file");
    }

    internal static void VerifyDirectoryAcl(string directoryPath)
    {
        EnsureNotReparsePoint(directoryPath);
        DirectoryInfo directoryInfo = new(directoryPath);
        DirectorySecurity security = directoryInfo.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        VerifySecurityDescriptor(security, "directory");
    }

    private static DirectorySecurity CreateOwnerOnlyDirectorySecurity()
    {
        SecurityIdentifier userSid = GetCurrentUserSid();
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static FileSecurity CreateOwnerOnlyFileSecurity()
    {
        SecurityIdentifier userSid = GetCurrentUserSid();
        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        return security;
    }

    private static void VerifySecurityDescriptor(FileSystemSecurity security, string targetKind)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier userSid = identity.User
            ?? throw new VaultStorageException("Unable to resolve current Windows user SID.");
        SecurityIdentifier ownerSid = identity.Owner ?? userSid;

        IdentityReference? fileOwner = security.GetOwner(typeof(SecurityIdentifier));
        if (fileOwner is null || (!fileOwner.Equals(userSid) && !fileOwner.Equals(ownerSid)))
        {
            throw new VaultStorageException($"Vault {targetKind} is not owned by the current Windows user.");
        }

        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));

        bool hasOwnerAllowRule = false;
        foreach (AuthorizationRule rule in rules)
        {
            if (rule is not FileSystemAccessRule fsRule || fsRule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }

            if (!fsRule.IdentityReference.Equals(userSid))
            {
                throw new VaultStorageException(
                    $"Vault {targetKind} permissions grant access to an unauthorized principal.");
            }

            hasOwnerAllowRule = true;
        }

        if (!hasOwnerAllowRule)
        {
            throw new VaultStorageException($"Vault {targetKind} has no allow rule for the current user.");
        }
    }
}
