namespace PasswordVault.Core.Session;

/// <summary>
/// Monotonic clock backed by <see cref="Environment.TickCount64"/>.
/// </summary>
public sealed class SystemClock : IClock
{
    public long ElapsedMilliseconds => Environment.TickCount64;
}
