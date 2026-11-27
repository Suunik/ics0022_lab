using PasswordVault.Core.Models;

namespace PasswordVault.Core.Security;

/// <summary>
/// Immutable Argon2id cost parameters validated against OWASP and ceiling limits.
/// </summary>
public sealed record VaultKdfParameters
{
    public static VaultKdfParameters Default { get; } = new(65536, 3, 1);

    public VaultKdfParameters(uint memoryKiB, uint iterations, uint parallelism)
    {
        VaultHeader.ValidateKdfParameters(memoryKiB, iterations, parallelism);
        MemoryKiB = memoryKiB;
        Iterations = iterations;
        Parallelism = parallelism;
    }

    public uint MemoryKiB { get; }

    public uint Iterations { get; }

    public uint Parallelism { get; }
}
