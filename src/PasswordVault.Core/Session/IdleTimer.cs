namespace PasswordVault.Core.Session;

/// <summary>
/// Tracks session inactivity using a monotonic clock.
/// </summary>
public sealed class IdleTimer
{
    private readonly IClock _clock;
    private readonly long _timeoutMilliseconds;
    private long _lastActivityMilliseconds;

    public IdleTimer(IClock clock, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(clock);
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "Idle timeout must be positive.");
        }

        _clock = clock;
        _timeoutMilliseconds = (long)timeout.TotalMilliseconds;
        _lastActivityMilliseconds = _clock.ElapsedMilliseconds;
    }

    public bool IsExpired => (_clock.ElapsedMilliseconds - _lastActivityMilliseconds) >= _timeoutMilliseconds;

    public TimeSpan Remaining
    {
        get
        {
            long elapsed = _clock.ElapsedMilliseconds - _lastActivityMilliseconds;
            long remainingMs = _timeoutMilliseconds - elapsed;
            return remainingMs <= 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(remainingMs);
        }
    }

    public void Reset()
    {
        _lastActivityMilliseconds = _clock.ElapsedMilliseconds;
    }
}
