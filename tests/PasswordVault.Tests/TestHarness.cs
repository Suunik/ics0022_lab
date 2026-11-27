using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using PasswordVault.Core.Models;
using PasswordVault.Core.Security;
using PasswordVault.Core.Session;

namespace PasswordVault.Tests;

internal sealed class FakeClock : IClock
{
    public long ElapsedMilliseconds { get; set; } = 1_000;

    public void Advance(TimeSpan delta)
    {
        ElapsedMilliseconds += (long)delta.TotalMilliseconds;
    }
}

internal sealed class FakeUserIdentityProvider : IUserIdentityProvider
{
    public string CurrentSid { get; set; } = new WindowsUserIdentityProvider().GetCurrentUserIdentifier();

    public string GetCurrentUserIdentifier() => CurrentSid;
}

internal static class TestHarness
{
    internal static VaultKdfParameters FastTestKdf { get; } = new(
        VaultHeader.MinMemoryKiB,
        VaultHeader.MinIterations,
        VaultHeader.MinParallelism);

    internal static string CreateTempDirectory()
    {
        return Path.Combine(Path.GetTempPath(), "pwm-test-" + Guid.NewGuid().ToString("N"));
    }

    internal static void DeleteDirectorySafe(string? path)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort temp cleanup after test run.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort temp cleanup after test run.
        }
    }

    internal static byte[] CreateSampleMasterBytes(int variant = 1)
    {
        string token = variant == 1
            ? "correct-horse-battery-staple-alpha"
            : "wrong-horse-battery-staple-beta-00";
        return Encoding.UTF8.GetBytes(token);
    }

    internal static byte[] CreateSampleSecretBytes(string label)
    {
        return Encoding.UTF8.GetBytes("sample-entry-secret-" + label);
    }

    internal static void GrantEveryoneReadAcl(string filePath)
    {
        FileInfo info = new(filePath);
        FileSecurity security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.ReadData,
            AccessControlType.Allow));
        info.SetAccessControl(security);
    }
}
