using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using PasswordVault.Core.Security;

namespace PasswordVault.App.Services;

/// <summary>
/// Copies secrets to the Windows clipboard and clears the clipboard automatically after 30 seconds or on lock.
/// </summary>
public sealed class SecureClipboardService : IClipboardService
{
    private static readonly TimeSpan ClearDelay = TimeSpan.FromSeconds(30);

    private readonly DispatcherTimer _clearTimer;
    private byte[]? _lastCopiedHash;
    private bool _disposed;

    public SecureClipboardService()
    {
        _clearTimer = new DispatcherTimer { Interval = ClearDelay };
        _clearTimer.Tick += OnClearTimerTick;
    }

    /// <inheritdoc />
    public void CopySecret(SecretBuffer secret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(secret);

        byte[] newHash = SHA256.HashData(secret.AsReadOnlySpan());
        string text = secret.ToUtf8String();

        Clipboard.SetText(text);

        if (_lastCopiedHash is not null)
        {
            CryptographicOperations.ZeroMemory(_lastCopiedHash);
        }

        _lastCopiedHash = newHash;
        _clearTimer.Stop();
        _clearTimer.Start();
    }

    /// <inheritdoc />
    public void ClearIfOwned()
    {
        if (_disposed)
        {
            return;
        }

        _clearTimer.Stop();
        if (_lastCopiedHash is null)
        {
            return;
        }

        try
        {
            if (Clipboard.ContainsText())
            {
                string currentText = Clipboard.GetText();
                byte[] currentHash = SHA256.HashData(Encoding.UTF8.GetBytes(currentText));
                if (CryptographicOperations.FixedTimeEquals(currentHash, _lastCopiedHash))
                {
                    Clipboard.Clear();
                }
            }
        }
        catch (ExternalException)
        {
            // Clipboard may be temporarily locked by another application; avoid crashing lock/exit flows.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(_lastCopiedHash);
            _lastCopiedHash = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        ClearIfOwned();
        _clearTimer.Tick -= OnClearTimerTick;
        _disposed = true;
    }

    private void OnClearTimerTick(object? sender, EventArgs e)
    {
        ClearIfOwned();
    }
}
