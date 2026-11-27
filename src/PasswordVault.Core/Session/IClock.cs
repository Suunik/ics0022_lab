namespace PasswordVault.Core.Session;

/// <summary>
/// Monotonic millisecond clock abstraction for session idle timeout tracking.
/// </summary>
public interface IClock
{
    long ElapsedMilliseconds { get; }
}
