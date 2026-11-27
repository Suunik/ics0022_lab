using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using PasswordVault.Core.Security;

namespace PasswordVault.App.Services;

/// <summary>
/// Converts WPF <see cref="SecureString"/> instances directly into a <see cref="SecretBuffer"/> without creating managed strings.
/// </summary>
internal static class SecureStringHelper
{
    public static SecretBuffer ToSecretBuffer(SecureString secureString)
    {
        ArgumentNullException.ThrowIfNull(secureString);

        int length = secureString.Length;
        if (length == 0)
        {
            return SecretBuffer.Allocate(0);
        }

        char[] chars = new char[length];
        IntPtr unmanagedPointer = IntPtr.Zero;

        try
        {
            unmanagedPointer = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            Marshal.Copy(unmanagedPointer, chars, 0, length);

            int utf8ByteCount = Encoding.UTF8.GetByteCount(chars);
            SecretBuffer buffer = SecretBuffer.Allocate(utf8ByteCount);
            try
            {
                Encoding.UTF8.GetBytes(chars, buffer.AsSpan());
                return buffer;
            }
            catch
            {
                buffer.Dispose();
                throw;
            }
        }
        finally
        {
            Array.Clear(chars);
            if (unmanagedPointer != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPointer);
            }
        }
    }
}
